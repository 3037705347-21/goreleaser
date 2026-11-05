// Package sign handles signing artifacts.
package sign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/caarlos0/log"
	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/gerrors"
	"github.com/goreleaser/goreleaser/v2/internal/gio"
	"github.com/goreleaser/goreleaser/v2/internal/git"
	"github.com/goreleaser/goreleaser/v2/internal/ids"
	"github.com/goreleaser/goreleaser/v2/internal/logext"
	"github.com/goreleaser/goreleaser/v2/internal/pipe"
	"github.com/goreleaser/goreleaser/v2/internal/redact"
	"github.com/goreleaser/goreleaser/v2/internal/semerrgroup"
	"github.com/goreleaser/goreleaser/v2/internal/skips"
	"github.com/goreleaser/goreleaser/v2/internal/tmpl"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
)

// Pipe that signs common artifacts.
type Pipe struct{}

func (Pipe) String() string { return "signing artifacts" }

func (Pipe) Skip(ctx *context.Context) bool {
	return skips.Any(ctx, skips.Sign) || len(ctx.Config.Signs) == 0
}

func (Pipe) Dependencies(ctx *context.Context) []string {
	var cmds []string
	for _, s := range ctx.Config.Signs {
		cmds = append(cmds, s.Cmd)
	}
	return cmds
}

const defaultGpg = "gpg"

// Default sets the Pipes defaults.
func (Pipe) Default(ctx *context.Context) error {
	gpgPath := sync.OnceValue(func() string {
		if gpg, _ := git.Clean(
			git.Run(ctx, "config", "gpg.program"),
		); gpg != "" {
			return gpg
		}
		return defaultGpg
	})

	ids := ids.New("signs")
	for i := range ctx.Config.Signs {
		cfg := &ctx.Config.Signs[i]
		if cfg.Cmd == "" {
			// gpgPath is either "gpg" (default) or the user's git config gpg.program value
			cfg.Cmd = gpgPath()
		}
		if cfg.Signature == "" {
			cfg.Signature = "${artifact}.sig"
		}
		if len(cfg.Args) == 0 {
			cfg.Args = []string{"--output", "$signature", "--detach-sig", "$artifact"}
		}
		if cfg.Artifacts == "" {
			cfg.Artifacts = "none"
		}
		if cfg.ID == "" {
			cfg.ID = "default"
		}
		ids.Inc(cfg.ID)
	}
	return ids.Validate()
}

// Run executes the Pipe.
func (Pipe) Run(ctx *context.Context) error {
	// skip-aware so that a config with `artifacts: none` doesn't mask the
	// errors of the other configs, and doesn't prevent the refresh below.
	g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	for i := range ctx.Config.Signs {
		cfg := ctx.Config.Signs[i]
		g.Go(func() error {
			var filters []artifact.Filter
			switch cfg.Artifacts {
			case "checksum":
				filters = append(filters, artifact.ByType(artifact.Checksum))
				if len(cfg.IDs) > 0 {
					log.Warn("when artifacts is `checksum`, `ids` has no effect. ignoring")
				}
			case "source":
				filters = append(filters, artifact.ByType(artifact.UploadableSourceArchive))
				if len(cfg.IDs) > 0 {
					log.Warn("when artifacts is `source`, `ids` has no effect. ignoring")
				}
			case "all":
				filters = append(
					filters,
					artifact.And(
						artifact.ByTypes(artifact.ReleaseUploadableTypes()...),
						artifact.Not(artifact.ByTypes(artifact.Signature, artifact.Certificate)),
					),
				)
			case "archive":
				filters = append(filters, artifact.ByType(artifact.UploadableArchive))
			case "binary":
				filters = append(filters, artifact.ByType(artifact.UploadableBinary))
			case "sbom":
				filters = append(filters, artifact.ByType(artifact.SBOM))
			case "package":
				filters = append(filters, artifact.ByType(artifact.LinuxPackage))
			case "none": // TODO(caarlos0): this is not very useful, lets remove it.
				return pipe.ErrSkipSignEnabled
			default:
				return fmt.Errorf("invalid list of artifacts to sign: %s", cfg.Artifacts)
			}

			filters = append(filters, artifact.ByIDs(cfg.IDs...))
			return sign(ctx, cfg, ctx.Artifacts.Filter(artifact.And(filters...)).List(), true)
		})
	}
	err := g.Wait()
	if err != nil && !pipe.IsSkip(err) {
		return err
	}

	if rerr := ctx.Artifacts.Refresh(); rerr != nil {
		return rerr
	}
	return err
}

// sign signs the given artifacts.
//
// When managed is true the artifacts are local files and their signatures
// are maintained as a machine-generated roster: on selective rebuilds,
// signatures are reused when the artifact content did not change and stale
// machine signatures are pruned. Docker images are signed remotely, so
// they are not part of the roster.
func sign(ctx *context.Context, cfg config.Sign, artifacts []*artifact.Artifact, managed bool) error {
	if len(artifacts) == 0 {
		log.Warn("no artifacts matching the given filters found")
	}

	reconcile := managed && ctx.Partial

	// expected holds the final paths of every signature and certificate
	// this config produces for the current artifacts. Machine-generated
	// outputs that are not in this set are pruned in partial runs.
	expected := map[string]struct{}{}

	for _, a := range artifacts {
		if err := a.Refresh(); err != nil {
			return err
		}

		var digest, sigPath, certPath string
		if managed {
			var err error
			digest, err = contentDigest(a.Path)
			if err != nil {
				return fmt.Errorf("sign failed: %s: %w", a.Name, err)
			}

			_, sigPath, certPath, err = renderTargets(ctx, cfg, a)
			if err != nil {
				return fmt.Errorf("sign failed: %s: %w", a.Name, err)
			}
			if sigPath != "" {
				expected[absPath(sigPath)] = struct{}{}
			}
			if certPath != "" {
				expected[absPath(certPath)] = struct{}{}
			}
		}

		// On selective rebuilds, reuse machine signatures generated for
		// the same artifact content instead of signing again.
		if reconcile && reusableOutputs(ctx, cfg.ID, a, digest, sigPath, certPath) {
			log.WithField("artifact", a.Name).Info("reusing signature")
			continue
		}

		results, err := signone(ctx, cfg, a, signOptions{
			managed: managed,
			digest:  digest,
			atomic:  reconcile,
		})
		if err != nil {
			return err
		}

		if reconcile {
			// Drop the previous machine outputs at these paths, so the
			// roster does not accumulate stale records. Manually
			// provided records are never removed.
			removeManagedOutputs(ctx, cfg.ID, sigPath, certPath)
		}
		for _, artifact := range results {
			ctx.Artifacts.Add(artifact)
		}
	}

	// On selective rebuilds, drop machine signatures that no longer
	// correspond to any current artifact. Manual signatures are kept.
	if reconcile {
		return pruneManagedOutputs(ctx, cfg.ID, expected)
	}
	return nil
}

// renderTargets builds the signing environment and renders the final
// signature and certificate paths for the given artifact.
func renderTargets(ctx *context.Context, cfg config.Sign, art *artifact.Artifact) (context.Env, string, string, error) {
	env := ctx.Env.Copy()
	env["artifactName"] = art.Name // shouldn't be used
	env["artifact"] = art.Path
	env["artifactID"] = art.ID()
	env["digest"] = artifact.ExtraOr(*art, artifact.ExtraDigest, "")

	tmplEnv, err := templateEnvS(ctx, cfg.Env)
	if err != nil {
		return nil, "", "", err
	}
	maps.Copy(env, context.ToEnv(tmplEnv))

	sigPath, err := tmplPath(ctx, env, art, cfg.Signature)
	if err != nil {
		return nil, "", "", err
	}
	env["signature"] = sigPath

	certPath, err := tmplPath(ctx, env, art, cfg.Certificate)
	if err != nil {
		return nil, "", "", err
	}
	env["certificate"] = certPath

	return env, sigPath, certPath, nil
}

// contentDigest returns the sha256 digest of the file at path.
func contentDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// absPath canonicalizes a possibly slashed, possibly relative path, so it
// can be compared against artifact paths as stored in the artifact list.
func absPath(p string) string {
	ap, err := filepath.Abs(filepath.FromSlash(p))
	if err != nil {
		return filepath.Clean(filepath.FromSlash(p))
	}
	return filepath.Clean(ap)
}

// reusableOutputs reports whether every signature and certificate the
// config produces for art already exists on disk, machine-generated for
// the same artifact content.
func reusableOutputs(ctx *context.Context, id string, art *artifact.Artifact, digest, sigPath, certPath string) bool {
	if sigPath != "" && !reusableOutput(ctx, id, art, digest, sigPath, artifact.Signature) {
		return false
	}
	if certPath != "" && !reusableOutput(ctx, id, art, digest, certPath, artifact.Certificate) {
		return false
	}
	return true
}

func reusableOutput(ctx *context.Context, id string, art *artifact.Artifact, digest, target string, typ artifact.Type) bool {
	target = absPath(target)
	for _, rec := range ctx.Artifacts.Filter(artifact.ByType(typ)).List() {
		switch {
		case rec.ID() != id:
			continue
		case !artifact.ExtraOr(*rec, artifact.ExtraSignManaged, false):
			continue
		case artifact.ExtraOr(*rec, artifact.ExtraSignArtifact, "") != art.Path:
			continue
		case artifact.ExtraOr(*rec, artifact.ExtraSignDigest, "") != digest:
			continue
		case absPath(rec.Path) != target:
			continue
		}
		if _, err := os.Stat(rec.Path); err != nil {
			continue
		}
		return true
	}
	return false
}

// removeManagedOutputs drops machine-generated signature and certificate
// records at the given paths. Manually provided records are left alone.
func removeManagedOutputs(ctx *context.Context, id string, paths ...string) {
	targets := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p != "" {
			targets[absPath(p)] = struct{}{}
		}
	}
	_ = ctx.Artifacts.Remove(func(a *artifact.Artifact) bool {
		if a.Type != artifact.Signature && a.Type != artifact.Certificate {
			return false
		}
		if a.ID() != id || !artifact.ExtraOr(*a, artifact.ExtraSignManaged, false) {
			return false
		}
		_, ok := targets[absPath(a.Path)]
		return ok
	})
}

// pruneManagedOutputs removes machine-generated signature and certificate
// records whose paths are not in expected, and deletes the corresponding
// files. Manually provided signatures are preserved.
func pruneManagedOutputs(ctx *context.Context, id string, expected map[string]struct{}) error {
	var stale []*artifact.Artifact
	for _, rec := range ctx.Artifacts.Filter(artifact.Or(
		artifact.ByType(artifact.Signature),
		artifact.ByType(artifact.Certificate),
	)).List() {
		if rec.ID() != id {
			continue
		}
		if !artifact.ExtraOr(*rec, artifact.ExtraSignManaged, false) {
			continue
		}
		if _, ok := expected[absPath(rec.Path)]; ok {
			continue
		}
		stale = append(stale, rec)
	}

	for _, rec := range stale {
		logger := log.WithField("name", rec.Name).WithField("type", rec.Type.String())
		if err := os.Remove(rec.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		logger.Info("removing stale machine signature")
		_ = ctx.Artifacts.Remove(func(a *artifact.Artifact) bool { return a == rec })
	}
	return nil
}

// tempOutput returns a temporary path in the same directory as target, so
// the signer output can later be atomically renamed onto target. Any
// leftover from an interrupted previous run is truncated, so reruns
// converge. The file is removed again: the signer creates it, with its
// usual permissions. A failed or interrupted signing therefore never
// touches the previous output at target.
func tempOutput(target string) (string, error) {
	tmp := target + ".goreleaser-tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(tmp); err != nil {
		return "", err
	}
	return tmp, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func relativeToDist(dist, f string) (string, error) {
	af, err := filepath.Abs(f)
	if err != nil {
		return "", err
	}
	df, err := filepath.Abs(dist)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(af, df) {
		return f, nil
	}
	return filepath.Join(dist, f), nil
}

func tmplPath(ctx *context.Context, env map[string]string, a *artifact.Artifact, s string) (string, error) {
	result, err := tmpl.New(ctx).WithArtifact(a).WithEnv(env).Apply(expand(s, env))
	if err != nil || result == "" {
		return "", err
	}
	return relativeToDist(ctx.Config.Dist, result)
}

type signOptions struct {
	// managed records the produced signatures and certificates as
	// machine-generated outputs tied to the signed artifact content.
	managed bool
	// digest is the sha256 content digest of the signed artifact.
	digest string
	// atomic makes the signer write to temporary files that are moved
	// into place only on success, so a failed or interrupted signing
	// keeps the previous signatures and certificates intact.
	atomic bool
}

func signone(ctx *context.Context, cfg config.Sign, art *artifact.Artifact, opts signOptions) ([]*artifact.Artifact, error) {
	env, sigPath, certPath, err := renderTargets(ctx, cfg, art)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
	}
	name, cert := sigPath, certPath

	// In atomic mode the signer writes to temporary files in the same
	// directory as the final outputs; they are renamed into place only
	// after the signer succeeds.
	var sigTmp, certTmp string
	if opts.atomic {
		if sigPath != "" {
			sigTmp, err = tempOutput(sigPath)
			if err != nil {
				return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
			}
			env["signature"] = sigTmp
			defer os.Remove(sigTmp)
		}
		if certPath != "" {
			certTmp, err = tempOutput(certPath)
			if err != nil {
				return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
			}
			env["certificate"] = certTmp
			defer os.Remove(certTmp)
		}
	}

	//nolint:prealloc
	var args []string
	for _, a := range cfg.Args {
		arg, err := tmpl.New(ctx).WithEnv(env).Apply(expand(a, env))
		if err != nil {
			return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
		}
		args = append(args, arg)
	}

	var stdin io.Reader
	if cfg.Stdin != nil {
		s, err := tmpl.New(ctx).WithEnv(env).Apply(expand(*cfg.Stdin, env))
		if err != nil {
			return nil, err
		}
		stdin = strings.NewReader(s)
	} else if cfg.StdinFile != "" {
		f, err := os.Open(cfg.StdinFile)
		if err != nil {
			return nil, fmt.Errorf("sign failed: cannot open file %s: %w", cfg.StdinFile, err)
		}
		defer f.Close()

		stdin = f
	}

	log := log.WithField("cmd", cfg.Cmd).WithField("artifact", art.Name)
	if name != "" {
		log = log.WithField("signature", name)
	}
	if cert != "" {
		log = log.WithField("certificate", cert)
	}

	output, err := tmpl.New(ctx).WithEnv(env).Bool(cfg.Output)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
	}

	// The GoASTScanner flags this as a security risk.
	// However, this works as intended. The nosec annotation
	// tells the scanner to ignore this.
	// #nosec
	cmd := exec.CommandContext(ctx, cfg.Cmd, args...)
	cmd.Env = env.Strings()

	var b bytes.Buffer
	w := gio.Safe(&b)
	stderr := redact.Writer(io.MultiWriter(logext.NewConditionalWriter(output), w), cmd.Env)
	stdout := redact.Writer(io.MultiWriter(logext.NewConditionalWriter(output), w), cmd.Env)
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	if stdin != nil {
		cmd.Stdin = stdin
	}
	log.Info("signing")
	runErr := cmd.Run()
	stderrErr := stderr.Close()
	stdoutErr := stdout.Close()
	if runErr != nil {
		return nil, gerrors.Wrap(
			runErr,
			gerrors.WithMessage("could not sign artifact"),
			gerrors.WithDetails(
				"cmd", cfg.Cmd,
				"artifact", art.Name,
			),
			gerrors.WithOutput(b.String()),
		)
	}
	if stderrErr != nil {
		return nil, stderrErr
	}
	if stdoutErr != nil {
		return nil, stdoutErr
	}

	// restore the final output paths before re-rendering names.
	if opts.atomic {
		env["signature"] = sigPath
		env["certificate"] = certPath
	}

	var result []*artifact.Artifact

	// re-execute template results, using artifact desc as artifact so they eval to the actual needed file desc.
	env["artifact"] = art.Name
	name, err = tmpl.New(ctx).WithArtifact(art).WithEnv(env).Apply(expand(cfg.Signature, env))
	if err != nil {
		return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
	}
	cert, err = tmpl.New(ctx).WithArtifact(art).WithEnv(env).Apply(expand(cfg.Certificate, env))
	if err != nil {
		return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
	}

	managedExtra := func() map[string]any {
		extra := map[string]any{
			artifact.ExtraID: cfg.ID,
		}
		if opts.managed {
			extra[artifact.ExtraSignManaged] = true
			extra[artifact.ExtraSignDigest] = opts.digest
			extra[artifact.ExtraSignArtifact] = art.Path
		}
		return extra
	}

	if cfg.Signature != "" {
		if opts.atomic {
			if fileExists(sigTmp) {
				if err := os.Rename(sigTmp, sigPath); err != nil {
					return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
				}
			} else {
				checkWritten(log, sigPath)
			}
		} else {
			checkWritten(log, sigPath)
		}
		result = append(result, &artifact.Artifact{
			Type:  artifact.Signature,
			Name:  name,
			Path:  sigPath,
			Extra: managedExtra(),
		})
	}

	if certPath != "" {
		if opts.atomic {
			if fileExists(certTmp) {
				if err := os.Rename(certTmp, certPath); err != nil {
					return nil, fmt.Errorf("sign failed: %s: %w", art.Name, err)
				}
			} else {
				checkWritten(log, certPath)
			}
		} else {
			checkWritten(log, certPath)
		}
		result = append(result, &artifact.Artifact{
			Type:  artifact.Certificate,
			Name:  cert,
			Path:  certPath,
			Extra: managedExtra(),
		})
	}

	return result, nil
}

// TODO(v3): fail instead of warning, and do not record the artifact.
//
// checkWritten warns when the signer did not write the file it was configured
// to write. The artifact is recorded anyway, pointing to a file that does not
// exist, which only fails much later, while uploading it.
func checkWritten(logger *log.Entry, path string) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		logger.Warnf("the signer did not write %s: this will be an error in v3", path)
	}
}

func expand(s string, env map[string]string) string {
	return os.Expand(s, func(key string) string {
		return env[key]
	})
}

func templateEnvS(ctx *context.Context, s []string) ([]string, error) {
	var out []string
	for _, s := range s {
		ts, err := tmpl.New(ctx).WithEnvS(out).Apply(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ts)
	}
	return out, nil
}
