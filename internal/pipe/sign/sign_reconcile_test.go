package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/internal/testlib"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
)

// digestFile returns the sha256 content digest used by the sign pipe.
func digestFile(tb testing.TB, path string) string {
	tb.Helper()
	bts, err := os.ReadFile(path)
	require.NoError(tb, err)
	sum := sha256.Sum256(bts)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signCalls(tb testing.TB, path string) int {
	tb.Helper()
	bts, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(bts)))
}

// managedRecord builds a machine-generated signature or certificate
// artifact record, as found in artifacts.json merged back in on selective
// rebuilds.
func managedRecord(cfgID, name, path, sourcePath, digest string, typ artifact.Type) *artifact.Artifact {
	return &artifact.Artifact{
		Name: name,
		Path: filepath.ToSlash(path),
		Type: typ,
		Extra: artifact.Extras{
			artifact.ExtraID:           cfgID,
			artifact.ExtraSignManaged:  true,
			artifact.ExtraSignDigest:   digest,
			artifact.ExtraSignArtifact: filepath.ToSlash(sourcePath),
		},
	}
}

// signerScript records every invocation in CALLS and copies the artifact
// into the signature, so signatures are deterministic.
const recordingSigner = `printf '%s\n' "$artifact" >> "$CALLS"; cat "$artifact" > "$signature"`

func partialChecksumCtx(tb testing.TB, dist, calls, script string) *context.Context {
	tb.Helper()
	cmd, args := shell(script)
	ctx := testctx.WrapWithCfg(tb.Context(), config.Project{
		Dist: dist,
		Signs: []config.Sign{{
			ID:        "default",
			Artifacts: "checksum",
			Cmd:       cmd,
			Args:      args,
			Env:       []string{"CALLS=" + calls},
		}},
	}, testctx.Partial)
	require.NoError(tb, Pipe{}.Default(ctx))
	return ctx
}

func addChecksum(tb testing.TB, ctx *context.Context, name string) {
	tb.Helper()
	path := filepath.Join(ctx.Config.Dist, name)
	require.NoError(tb, os.WriteFile(path, []byte("foo"), 0o644))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: name,
		Path: path,
		Type: artifact.Checksum,
	})
}

func signatureArtifacts(ctx *context.Context) []*artifact.Artifact {
	return ctx.Artifacts.Filter(artifact.ByType(artifact.Signature)).List()
}

// Unchanged artifacts are not signed again on selective rebuilds; changed
// artifacts are signed again, and the roster converges to a single record.
func TestPartialSignReuseAndResign(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	ctx := partialChecksumCtx(t, dist, calls, recordingSigner)
	addChecksum(t, ctx, "checksums.txt")

	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls), "first run signs")
	sigPath := filepath.Join(dist, "checksums.txt.sig")
	require.Equal(t, "foo", readFile(t, sigPath))
	require.Len(t, signatureArtifacts(ctx), 1)

	// rerun with the exact same artifact content: signer is not invoked.
	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls), "unchanged content reuses the signature")
	require.Len(t, signatureArtifacts(ctx), 1)

	// artifact content changes: the signature is generated again.
	require.NoError(t, os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte("bar"), 0o644))
	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 2, signCalls(t, calls), "changed content is signed again")
	require.Equal(t, "bar", readFile(t, sigPath))
	require.Len(t, signatureArtifacts(ctx), 1)
	sig := signatureArtifacts(ctx)[0]
	require.Equal(t, digestFile(t, filepath.Join(dist, "checksums.txt")), artifact.ExtraOr(*sig, artifact.ExtraSignDigest, ""))
	require.True(t, artifact.ExtraOr(*sig, artifact.ExtraSignManaged, false))
}

// Machine signatures without a current artifact are pruned, but manually
// provided signatures are preserved both as artifacts and on disk.
func TestPartialSignPrunesMachineKeepsManual(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	ctx := partialChecksumCtx(t, dist, calls, recordingSigner)

	keep := filepath.Join(dist, "keep.txt")
	require.NoError(t, os.WriteFile(keep, []byte("foo"), 0o644))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "keep.txt",
		Path: keep,
		Type: artifact.Checksum,
	})

	// reusable machine signature for keep.txt.
	keepSig := filepath.Join(dist, "keep.txt.sig")
	require.NoError(t, os.WriteFile(keepSig, []byte("foo"), 0o644))
	ctx.Artifacts.Add(managedRecord("default", "keep.txt.sig", keepSig, keep, digestFile(t, keep), artifact.Signature))

	// stale machine signature: its artifact is no longer produced.
	gone := filepath.Join(dist, "gone.txt")
	goneSig := filepath.Join(dist, "gone.txt.sig")
	require.NoError(t, os.WriteFile(goneSig, []byte("old"), 0o644))
	ctx.Artifacts.Add(managedRecord("default", "gone.txt.sig", goneSig, gone, "sha256:deadbeef", artifact.Signature))

	// manually provided historical signature: not machine-marked.
	manualSig := filepath.Join(dist, "manual.txt.sig")
	require.NoError(t, os.WriteFile(manualSig, []byte("manual"), 0o644))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "manual.txt.sig",
		Path: manualSig,
		Type: artifact.Signature,
		Extra: artifact.Extras{
			artifact.ExtraID: "default",
		},
	})

	require.NoError(t, Pipe{}.Run(ctx))

	require.Equal(t, 0, signCalls(t, calls), "the existing machine signature is reused")

	require.NoFileExists(t, goneSig, "stale machine signature file is removed")
	require.FileExists(t, manualSig, "manual signature file is preserved")
	require.FileExists(t, keepSig, "reused signature file is kept")

	var names []string
	for _, sig := range signatureArtifacts(ctx) {
		names = append(names, sig.Name)
	}
	require.ElementsMatch(t, []string{"keep.txt.sig", "manual.txt.sig"}, names)
}

// When the signer fails after writing its output, the previous signature
// is untouched because the signer writes to a temporary file. A rerun
// converges to a signature matching the current content.
func TestPartialSignFailureKeepsPreviousSignature(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	ctx := partialChecksumCtx(t, dist, calls, recordingSigner)
	addChecksum(t, ctx, "checksums.txt")

	require.NoError(t, Pipe{}.Run(ctx))
	sigPath := filepath.Join(dist, "checksums.txt.sig")
	require.Equal(t, "foo", readFile(t, sigPath))

	// content changes, but the signer writes output and then fails.
	require.NoError(t, os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte("bar"), 0o644))
	ctx.Config.Signs[0].Cmd, ctx.Config.Signs[0].Args = shell(`cat "$artifact" > "$signature"; exit 1`)
	require.Error(t, Pipe{}.Run(ctx))
	require.Equal(t, "foo", readFile(t, sigPath), "previous signature is preserved")
	require.Len(t, signatureArtifacts(ctx), 1, "previous roster record is preserved")

	// rerun with a working signer converges.
	ctx.Config.Signs[0].Cmd, ctx.Config.Signs[0].Args = shell(recordingSigner)
	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, "bar", readFile(t, sigPath))
	require.Len(t, signatureArtifacts(ctx), 1)
}

// An interrupted signer (killed while writing) must not clobber the
// previous signature.
func TestPartialSignInterruptedKeepsPreviousSignature(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	ctx := partialChecksumCtx(t, dist, calls, recordingSigner)
	addChecksum(t, ctx, "checksums.txt")

	require.NoError(t, Pipe{}.Run(ctx))
	sigPath := filepath.Join(dist, "checksums.txt.sig")

	require.NoError(t, os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte("bar"), 0o644))
	ctx.Config.Signs[0].Cmd, ctx.Config.Signs[0].Args = shell(`cat "$artifact" > "$signature"; kill -9 $$`)
	require.Error(t, Pipe{}.Run(ctx))
	require.Equal(t, "foo", readFile(t, sigPath), "previous signature is preserved")
	require.NoFileExists(t, sigPath+".goreleaser-tmp", "temporary output is cleaned up")
}

// Signature and certificate are both reused and both replaced atomically.
func TestPartialSignSignatureAndCertificate(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	script := `printf '%s\n' "$artifact" >> "$CALLS"; cat "$artifact" > "$signature"; cat "$artifact" > "$certificate"`
	ctx := partialChecksumCtx(t, dist, calls, script)
	ctx.Config.Signs[0].Certificate = "${artifact}.pem"
	addChecksum(t, ctx, "checksums.txt")

	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls))
	certPath := filepath.Join(dist, "checksums.txt.pem")
	require.Equal(t, "foo", readFile(t, certPath))

	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls), "signature and certificate are reused")

	require.NoError(t, os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte("bar"), 0o644))
	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 2, signCalls(t, calls), "both are regenerated on content change")
	require.Equal(t, "bar", readFile(t, filepath.Join(dist, "checksums.txt.sig")))
	require.Equal(t, "bar", readFile(t, certPath))
	require.Len(t, signatureArtifacts(ctx), 1)
	require.Len(t, ctx.Artifacts.Filter(artifact.ByType(artifact.Certificate)).List(), 1)
}

// Non-partial, full signing keeps signing every artifact and does not
// prune pre-existing machine signatures.
func TestFullSignKeepsOriginalBehavior(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	cmd, args := shell(recordingSigner)
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist: dist,
		Signs: []config.Sign{{
			ID:        "default",
			Artifacts: "checksum",
			Cmd:       cmd,
			Args:      args,
			Env:       []string{"CALLS=" + calls},
		}},
	})
	require.NoError(t, Pipe{}.Default(ctx))
	addChecksum(t, ctx, "checksums.txt")

	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls))

	// unchanged content is signed again in a full run.
	require.NoError(t, Pipe{}.Run(ctx))
	require.Equal(t, 2, signCalls(t, calls), "full runs always sign")
}

// Full runs do not reconcile the roster: stale machine signatures from a
// merged roster are left alone.
func TestFullSignDoesNotPruneStaleSignatures(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	cmd, args := shell(recordingSigner)
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist: dist,
		Signs: []config.Sign{{
			ID:        "default",
			Artifacts: "checksum",
			Cmd:       cmd,
			Args:      args,
			Env:       []string{"CALLS=" + calls},
		}},
	})
	require.NoError(t, Pipe{}.Default(ctx))
	addChecksum(t, ctx, "keep.txt")

	gone := filepath.Join(dist, "gone.txt")
	goneSig := filepath.Join(dist, "gone.txt.sig")
	require.NoError(t, os.WriteFile(goneSig, []byte("old"), 0o644))
	ctx.Artifacts.Add(managedRecord("default", "gone.txt.sig", goneSig, gone, "sha256:deadbeef", artifact.Signature))

	require.NoError(t, Pipe{}.Run(ctx))
	require.FileExists(t, goneSig, "full runs do not prune stale machine signatures")
	require.Len(t, signatureArtifacts(ctx), 2)
}

// Binary signing also reuses signatures for unchanged binaries on
// selective rebuilds.
func TestPartialBinarySignReuses(t *testing.T) {
	testlib.SkipIfWindows(t, "uses /bin/sh")
	dist := t.TempDir()
	calls := filepath.Join(dist, "calls")
	cmd, args := shell(recordingSigner)
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist: dist,
		BinarySigns: []config.BinarySign{{
			ID:        "default",
			Artifacts: "binary",
			Cmd:       cmd,
			Args:      args,
			Env:       []string{"CALLS=" + calls},
		}},
	}, testctx.Partial)
	require.NoError(t, BinaryPipe{}.Default(ctx))

	bin := filepath.Join(dist, "bin")
	require.NoError(t, os.WriteFile(bin, []byte("foo"), 0o644))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "bin",
		Path: bin,
		Type: artifact.Binary,
	})

	require.NoError(t, BinaryPipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls))
	require.NoError(t, BinaryPipe{}.Run(ctx))
	require.Equal(t, 1, signCalls(t, calls), "unchanged binary signature is reused")
}

func readFile(tb testing.TB, path string) string {
	tb.Helper()
	bts, err := os.ReadFile(path)
	require.NoError(tb, err)
	return string(bts)
}
