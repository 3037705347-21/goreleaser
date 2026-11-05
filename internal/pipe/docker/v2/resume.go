package docker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/caarlos0/log"
	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/gerrors"
	"github.com/goreleaser/goreleaser/v2/internal/gio"
	"github.com/goreleaser/goreleaser/v2/internal/logext"
	"github.com/goreleaser/goreleaser/v2/internal/pipe"
	"github.com/goreleaser/goreleaser/v2/internal/redact"
	"github.com/goreleaser/goreleaser/v2/internal/retryx"
	"github.com/goreleaser/goreleaser/v2/internal/semerrgroup"
	"github.com/goreleaser/goreleaser/v2/internal/tmpl"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
)

const (
	// stagingTagPrefix is the fixed prefix of the internal, per-platform
	// staging tags used to resume multi-platform publishes.
	stagingTagPrefix = "goreleaser-stage-"

	// fingerprintVersion is bumped when the fingerprint inputs change.
	fingerprintVersion = "goreleaser-dockersv2-resume-v1"

	// fingerprintTagLen is how many fingerprint hex chars are embedded in
	// the staging tag name.
	fingerprintTagLen = 12
)

// resolvedDocker is the fully rendered view of a dockers_v2 config used by a
// single publish run.
type resolvedDocker struct {
	cfg         config.DockerV2
	dockerfile  string
	images      []string
	tags        []string
	platforms   []string
	labels      map[string]string
	annotations map[string]string
	buildArgs   map[string]string
	flags       []string
	sbom        bool
	base        dockerImage
}

// releasePlan identifies a publish across reruns and derives its per-repo
// final and staging references.
type releasePlan struct {
	key       string
	images    []string
	tags      []string
	platforms []string
}

type platformResult struct {
	platform    string
	fingerprint string
	// digests by image repository reference.
	digests map[string]string
}

// useResumablePublish reports whether the configuration goes through the
// per-platform staging flow: it must be enabled (default) and resolve to more
// than one platform. Single-platform configs keep the one-shot buildx build
// behavior.
func useResumablePublish(ctx *context.Context, d config.DockerV2) (bool, error) {
	enabled, err := tmpl.New(ctx).Bool(d.Resume)
	if err != nil {
		return false, fmt.Errorf("dockers_v2.resume: %w", err)
	}
	if !enabled {
		return false, nil
	}
	platforms := slices.Clone(d.Platforms)
	if err := tmpl.New(ctx).ApplySlice(&platforms, tmpl.NonEmpty()); err != nil {
		return false, err
	}
	return len(dedupe(platforms)) > 1, nil
}

func resolveDocker(ctx *context.Context, d config.DockerV2) (resolvedDocker, error) {
	tpl := tmpl.New(ctx)

	disable, err := tpl.Bool(d.Disable)
	if err != nil {
		return resolvedDocker{}, err
	}
	if disable {
		return resolvedDocker{}, pipe.Skip("configuration is disabled")
	}

	dockerfile, err := tpl.Apply(d.Dockerfile)
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid dockerfile: %w", err)
	}

	baseImg, baseErr := getBaseImage(ctx, dockerfile, d.BuildArgs)
	if baseErr != nil && !errors.Is(baseErr, errNoBaseImage) {
		log.WithField("dockerfile", d.Dockerfile).
			WithError(baseErr).
			Debug("could not resolve base image")
	}

	tpl = tpl.WithExtraFields(tmpl.Fields{
		keyBaseImage:       baseImg.name,
		keyBaseImageDigest: baseImg.digest,
	})

	images, err := tpl.Slice(d.Images, tmpl.NonEmpty())
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid images: %w", err)
	}
	if len(images) == 0 {
		return resolvedDocker{}, pipe.Skip("no images")
	}
	if _, ok := errors.AsType[tmpl.Error](baseErr); ok {
		return resolvedDocker{}, fmt.Errorf("invalid build args: %w", baseErr)
	}

	tags, err := tpl.Slice(d.Tags, tmpl.NonEmpty())
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid tags: %w", err)
	}
	if len(tags) == 0 {
		return resolvedDocker{}, errors.New("no tags provided")
	}

	labels, err := renderMap(tpl, d.Labels)
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid labels: %w", err)
	}
	annotations, err := renderMap(tpl, d.Annotations)
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid annotations: %w", err)
	}
	buildArgs, err := renderMap(tpl, d.BuildArgs)
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid build args: %w", err)
	}
	flags, err := tpl.Slice(d.Flags, tmpl.NonEmpty())
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("invalid flags: %w", err)
	}

	platforms := slices.Clone(d.Platforms)
	if err := tpl.ApplySlice(&platforms, tmpl.NonEmpty()); err != nil {
		return resolvedDocker{}, err
	}
	platforms = dedupe(platforms)

	sbom, err := tpl.Bool(d.SBOM)
	if err != nil {
		return resolvedDocker{}, fmt.Errorf("dockers_v2.sbom: %w", err)
	}

	return resolvedDocker{
		cfg:         d,
		dockerfile:  dockerfile,
		images:      images,
		tags:        tags,
		platforms:   platforms,
		labels:      labels,
		annotations: annotations,
		buildArgs:   buildArgs,
		flags:       flags,
		sbom:        sbom,
		base:        baseImg,
	}, nil
}

// publishResumable builds and pushes every current platform into
// content-addressed staging tags, reusing platforms that are already present,
// and only then promotes the final tags to the complete multi-platform index.
func publishResumable(ctx *context.Context, rd resolvedDocker) error {
	plan := releasePlan{
		key:       releaseKey(ctx.Version, rd.tags),
		images:    rd.images,
		tags:      rd.tags,
		platforms: rd.platforms,
	}
	createAnn := createAnnotations(rd.annotations)

	results := make([]platformResult, len(rd.platforms))
	g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	for i, plat := range rd.platforms {
		i, plat := i, plat
		g.Go(func() error {
			res, err := publishPlatform(ctx, rd, plan, plat)
			if err != nil {
				return err
			}
			results[i] = res
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	return promote(ctx, rd, plan, results, createAnn)
}

func publishPlatform(ctx *context.Context, rd resolvedDocker, plan releasePlan, plat string) (platformResult, error) {
	d := rd.cfg
	d.Platforms = []string{plat}

	wd, err := makeContext(d, contextArtifacts(ctx, d), rd.dockerfile)
	if err != nil {
		return platformResult{}, err
	}
	defer os.RemoveAll(wd)

	fp, err := contentFingerprint(wd, fingerprintInput{
		platform:    plat,
		sbom:        rd.sbom,
		labels:      rd.labels,
		annotations: rd.annotations,
		buildArgs:   rd.buildArgs,
		flags:       rd.flags,
		baseName:    rd.base.name,
		baseDigest:  rd.base.digest,
	})
	if err != nil {
		return platformResult{}, fmt.Errorf("could not calculate content fingerprint: %w", err)
	}

	result := platformResult{
		platform:    plat,
		fingerprint: fp,
		digests:     map[string]string{},
	}
	var missingImages []string
	var missingRefs []string
	for _, img := range plan.images {
		ref := stagingRef(img, plan.key, plat, fp)
		if digest, ok := inspectStage(ctx, ref); ok {
			log.WithField("id", rd.cfg.ID).
				WithField("platform", plat).
				WithField("image", img).
				Info("reusing previously pushed platform image")
			result.digests[img] = digest
			continue
		}
		missingImages = append(missingImages, img)
		missingRefs = append(missingRefs, ref)
	}

	if len(missingRefs) == 0 {
		return result, nil
	}

	log.WithField("id", rd.cfg.ID).
		WithField("platform", plat).
		WithField("images", strings.Join(missingRefs, "\n")).
		Info("building platform image")

	digest, err := buildStaging(ctx, rd, wd, plat, missingRefs)
	if err != nil {
		return platformResult{}, err
	}
	// a single build pushes the exact same content to every target repo, so
	// its digest is identical across them.
	for _, img := range missingImages {
		result.digests[img] = digest
	}
	return result, nil
}

// buildStaging builds one platform and pushes it to the given staging tags.
func buildStaging(ctx *context.Context, rd resolvedDocker, wd, plat string, targets []string) (string, error) {
	arg := []string{"buildx", "build", "--platform", plat}
	for _, t := range targets {
		arg = append(arg, "-t", t)
	}
	arg = append(arg, "--push")
	if rd.sbom {
		arg = append(arg, "--attest=type=sbom")
	}
	arg = append(arg, "--iidfile=id.txt")
	arg = append(arg, "--metadata-file=metadata.json")
	arg = append(arg, mapFlags("--label", rd.labels)...)
	arg = append(arg, buildAnnotations(rd.annotations, plat)...)
	arg = append(arg, mapFlags("--build-arg", rd.buildArgs)...)
	arg = append(arg, rd.flags...)
	arg = append(arg, ".")

	hookFields := tmpl.Fields{
		keyImages:     targets,
		keyDockerfile: rd.dockerfile,
		keyContextDir: wd,
	}
	if err := runHook(ctx, hookFields, rd.cfg.Hooks.Pre); err != nil {
		return "", fmt.Errorf("pre hook failed: %w", err)
	}

	digest, err := doBuild(ctx, rd.cfg, wd, arg)
	if err != nil {
		return "", err
	}

	hookFields[keyDigest] = digest
	if err := runHook(ctx, hookFields, rd.cfg.Hooks.Post); err != nil {
		return "", fmt.Errorf("post hook failed: %w", err)
	}
	return digest, nil
}

// promote assembles the final multi-platform index for every target image
// once every platform is ready, and records the resulting artifacts.
func promote(ctx *context.Context, rd resolvedDocker, plan releasePlan, results []platformResult, createAnn []string) error {
	digests := map[string]map[string]string{} // platform -> image -> digest
	fingerprints := map[string]string{}       // platform -> fingerprint
	for _, res := range results {
		digests[res.platform] = res.digests
		fingerprints[res.platform] = res.fingerprint
	}
	for _, plat := range plan.platforms {
		for _, img := range plan.images {
			if digests[plat][img] == "" {
				return fmt.Errorf("cannot promote %s: missing digest for platform %s", img, plat)
			}
		}
	}

	g := semerrgroup.NewSkipAware(semerrgroup.New(ctx.Parallelism))
	for _, img := range plan.images {
		g.Go(func() error {
			tmp, err := os.MkdirTemp("", "goreleaserdocker")
			if err != nil {
				return fmt.Errorf("failed to create temporary dir: %w", err)
			}
			defer os.RemoveAll(tmp)
			metaPath := filepath.Join(tmp, "metadata.json")

			arg := []string{"create", "--metadata-file=" + metaPath}
			for _, tag := range plan.tags {
				arg = append(arg, "-t", img+":"+tag)
			}
			arg = append(arg, createAnn...)
			for _, plat := range plan.platforms {
				source := stagingRef(img, plan.key, plat, fingerprints[plat]) + "@" + digests[plat][img]
				arg = append(arg, source)
			}

			if err := retryx.Do(
				ctx,
				rd.cfg.Retry,
				func() error {
					log.WithField("id", rd.cfg.ID).
						WithField("image", img).
						WithField("tags", strings.Join(plan.tags, ",")).
						Info("promoting multi-platform image tags")
					_, err := execImagetools(ctx, arg...)
					return err
				},
				isRetriableImagetools,
			); err != nil {
				return err
			}

			digest, err := promotedDigest(metaPath)
			if err != nil {
				return fmt.Errorf("could not get image digest: %w", err)
			}

			for _, tag := range plan.tags {
				name := img + ":" + tag
				ctx.Artifacts.Add(&artifact.Artifact{
					Name: name,
					Path: name,
					Type: artifact.DockerImageV2,
					Extra: map[string]any{
						artifact.ExtraID:     rd.cfg.ID,
						artifact.ExtraDigest: digest,
						ExtraPlatforms:       slices.Clone(plan.platforms),
					},
				})
			}
			return nil
		})
	}
	return g.Wait()
}

// promotedDigest reads the index digest written by imagetools create.
func promotedDigest(path string) (string, error) {
	bts, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var meta struct {
		Descriptor struct {
			Digest string `json:"digest"`
		} `json:"containerimage.descriptor"`
	}
	if err := json.Unmarshal(bts, &meta); err != nil {
		return "", err
	}
	if meta.Descriptor.Digest == "" {
		return "", errors.New("metadata file has no containerimage.descriptor.digest")
	}
	return meta.Descriptor.Digest, nil
}

// execImagetools runs a `docker buildx imagetools` command, returning its raw
// stdout (used by `inspect --raw`).
func execImagetools(ctx *context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"buildx", "imagetools"}, args...)...)
	cmd.Env = append(cmd.Environ(), ctx.Env.Strings()...)

	// stdout carries raw registry payloads (e.g. `imagetools inspect
	// --raw`), so it must not go through the log formatter. Stderr is still
	// streamed to the log and captured for error details.
	var stdout, stderr bytes.Buffer
	cmd.Stderr = redact.Writer(io.MultiWriter(logext.NewWriter(), gio.Safe(&stderr)), cmd.Env)
	cmd.Stdout = redact.Writer(gio.Safe(&stdout), cmd.Env)
	if err := cmd.Run(); err != nil {
		return nil, gerrors.Wrap(
			err,
			gerrors.WithMessage("docker buildx imagetools failed"),
			gerrors.WithOutput(stderr.String()),
			gerrors.WithDetails("args", strings.Join(cmd.Args, " ")),
		)
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

// inspectStage checks whether the expected content-addressed staging tag
// already exists in the registry. Any failure is treated as a cache miss, so
// the platform gets rebuilt instead of failing the whole publish.
func inspectStage(ctx *context.Context, ref string) (string, bool) {
	raw, err := execImagetools(ctx, "inspect", "--raw", ref)
	if err != nil || len(raw) == 0 {
		log.WithField("ref", ref).
			WithError(err).
			Debug("staging tag not reusable")
		return "", false
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

func isRetriableImagetools(err error) bool {
	return retryx.IsNetworkError(err) || IsRetriableBuild(err)
}

// --- planning helpers ---

func releaseKey(version string, tags []string) string {
	sorted := dedupe(slices.Clone(tags))
	slices.Sort(sorted)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s", version, strings.Join(sorted, "\x00"))
	return hex.EncodeToString(h.Sum(nil))[:fingerprintTagLen]
}

func platformSlug(platform string) string {
	return strings.ReplaceAll(platform, "/", "-")
}

func stagingName(key, platform, fingerprint string) string {
	return stagingTagPrefix + key + "-" + platformSlug(platform) + "-" + fingerprint[:fingerprintTagLen]
}

func stagingRef(image, key, platform, fingerprint string) string {
	return image + ":" + stagingName(key, platform, fingerprint)
}

// dedupe returns s without duplicates, preserving first-seen order.
func dedupe(s []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// renderMap templates all keys and values, skipping empty entries.
// Iteration follows sorted keys.
func renderMap(tpl *tmpl.Template, m map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		key, value := k, m[k]
		if err := tpl.ApplyAll(&key, &value); err != nil {
			return nil, err
		}
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		out[key] = value
	}
	return out, nil
}

func mapFlags(flag string, m map[string]string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, flag, k+"="+m[k])
	}
	return out
}

// --- content fingerprint ---

type fingerprintInput struct {
	platform    string
	sbom        bool
	labels      map[string]string
	annotations map[string]string
	buildArgs   map[string]string
	flags       []string
	baseName    string
	baseDigest  string
}

// fingerprintJSON is serialized with stable (sorted) map keys.
type fingerprintJSON struct {
	Version     string            `json:"version"`
	Platform    string            `json:"platform"`
	SBOM        bool              `json:"sbom"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	BuildArgs   map[string]string `json:"build_args"`
	Flags       []string          `json:"flags"`
	BaseName    string            `json:"base_name"`
	BaseDigest  string            `json:"base_digest"`
}

func contentFingerprint(wd string, in fingerprintInput) (string, error) {
	h := sha256.New()
	io.WriteString(h, fingerprintVersion+"\n")

	var files []string
	err := filepath.WalkDir(wd, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.Type().IsRegular() {
			rel, err := filepath.Rel(wd, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	slices.Sort(files)
	for _, rel := range files {
		bts, err := os.ReadFile(filepath.Join(wd, rel))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "file %s %d\n", filepath.ToSlash(rel), len(bts))
		h.Write(bts)
		h.Write([]byte{0})
	}

	encoded, err := json.Marshal(fingerprintJSON{
		Version:     fingerprintVersion,
		Platform:    in.platform,
		SBOM:        in.sbom,
		Labels:      in.labels,
		Annotations: in.annotations,
		BuildArgs:   in.buildArgs,
		Flags:       in.flags,
		BaseName:    in.baseName,
		BaseDigest:  in.baseDigest,
	})
	if err != nil {
		return "", err
	}
	h.Write(encoded)
	h.Write([]byte{0})

	return hex.EncodeToString(h.Sum(nil)), nil
}

// --- annotation partitioning ---

var knownAnnotationScopes = map[string]struct{}{
	"index":               {},
	"index-descriptor":    {},
	"manifest":            {},
	"manifest-descriptor": {},
}

type annotationScope struct {
	name      string
	qualifier string
}

// buildAnnotations returns the --annotation flags applied to a single
// per-platform build: manifest and manifest-descriptor scoped keys, filtered
// by the given platform. Index scoped annotations are applied later by
// imagetools create; annotations with unknown scopes are passed through
// unchanged so buildx keeps validating them as it does today.
func buildAnnotations(m map[string]string, platform string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		scopes, key, value, scoped := parseAnnotation(k, m[k])
		if !scoped {
			// unscoped annotations default to the index on multi-platform
			// builds; they are applied at promotion time.
			continue
		}
		unknownScope := false
		for _, s := range scopes {
			if _, ok := knownAnnotationScopes[s.name]; !ok {
				unknownScope = true
				break
			}
		}
		if unknownScope {
			out = append(out, "--annotation", k+"="+value)
			continue
		}
		for _, s := range scopes {
			if s.name != "manifest" && s.name != "manifest-descriptor" {
				continue
			}
			if s.qualifier != "" && s.qualifier != platform {
				continue
			}
			flag := s.name
			if s.qualifier != "" {
				flag += "[" + s.qualifier + "]"
			}
			out = append(out, "--annotation", flag+":"+key+"="+value)
		}
	}
	return out
}

// createAnnotations returns the --annotation flags applied when creating the
// final index. Only the index scope is supported by imagetools create;
// index-descriptor has no parent descriptor for a root index push, and
// manifest scopes are already baked into the per-platform images.
func createAnnotations(m map[string]string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		scopes, key, value, scoped := parseAnnotation(k, m[k])
		if !scoped {
			out = append(out, "--annotation", "index:"+key+"="+value)
			continue
		}
		hasIndex := false
		unknownScope := false
		for _, s := range scopes {
			switch s.name {
			case "index":
				hasIndex = true
			case "manifest", "manifest-descriptor", "index-descriptor":
			default:
				unknownScope = true
			}
		}
		if hasIndex && !unknownScope {
			out = append(out, "--annotation", "index:"+key+"="+value)
		}
	}
	return out
}

func parseAnnotation(key, value string) ([]annotationScope, string, string, bool) {
	prefix, bareKey, ok := strings.Cut(key, ":")
	if !ok {
		return nil, key, value, false
	}
	var scopes []annotationScope
	for _, part := range strings.Split(prefix, ",") {
		name, qualifier, _ := strings.Cut(part, "[")
		qualifier = strings.TrimSuffix(qualifier, "]")
		scopes = append(scopes, annotationScope{name: name, qualifier: qualifier})
	}
	return scopes, bareKey, value, true
}
