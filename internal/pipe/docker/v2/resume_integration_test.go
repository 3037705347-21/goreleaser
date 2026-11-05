package docker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/internal/testlib"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
	"github.com/stretchr/testify/require"
)

const resumeDockerfile = "FROM scratch\nARG TARGETPLATFORM\nCOPY $TARGETPLATFORM/mybin /mybin\n"

func TestResumeMultiArchPublish(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "registry images only available for windows")
	testlib.StartRegistry(t, "resume-registry", "5062")

	work, _ := isolatedDockerContextTemp(t)
	require.NoError(t, os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(resumeDockerfile), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-amd64"), []byte("amd64-binary-v1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-arm64"), []byte("arm64-binary-v1"), 0o644))

	logPath := filepath.Join(t.TempDir(), "docker.log")
	installDockerCountShim(t, t.TempDir(), logPath, false)

	newCtx := func(t *testing.T) *context.Context {
		t.Helper()
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			ProjectName: "resume",
			DockersV2: []config.DockerV2{{
				ID:         "app",
				Dockerfile: "Dockerfile",
				Images:     []string{"localhost:5062/app"},
				Tags:       []string{"v1.0.0", "latest"},
				Platforms:  []string{"linux/amd64", "linux/arm64"},
				Resume:     "true",
				SBOM:       "true",
				Annotations: map[string]string{
					"index:org.opencontainers.image.description": "resume test",
					"manifest[linux/amd64]:com.example.arch":     "amd64",
				},
			}},
		},
			testctx.WithVersion("1.0.0"),
			testctx.WithCurrentTag("v1.0.0"),
			testctx.WithSemver(1, 0, 0, ""),
		)
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-amd64", Goos: "linux", Goarch: "amd64", Type: artifact.Binary})
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-arm64", Goos: "linux", Goarch: "arm64", Type: artifact.Binary})
		return ctx
	}

	// run 1: fresh publish, both platforms built and promoted.
	ctx1 := newCtx(t)
	require.NoError(t, Base{}.Default(ctx1))
	require.NoError(t, Publish{}.Publish(ctx1))

	final := "localhost:5062/app:v1.0.0"
	idx := inspectIndex(t, final)
	platformsOf(t, idx, "linux/amd64", "linux/arm64")
	require.True(t, hasSBOM(t, final))
	require.Equal(t, map[string]string{"com.example.arch": "amd64"},
		manifestAnnotationsOf(t, idx, final, "linux/amd64"))
	require.Empty(t, manifestAnnotationsOf(t, idx, final, "linux/arm64"))

	tags1 := registryTagList(t, "5062", "app")
	var stageTags1 []string
	for _, tag := range tags1 {
		if strings.HasPrefix(tag, stagingTagPrefix) {
			stageTags1 = append(stageTags1, tag)
			continue
		}
		require.Contains(t, []string{"v1.0.0", "latest"}, tag, "unexpected tag: %s", tag)
	}
	slices.Sort(stageTags1)
	require.Len(t, stageTags1, 2)
	require.Contains(t, stageTags1[0], "linux-amd64-")
	require.Contains(t, stageTags1[1], "linux-arm64-")

	finalDigest1, ok := inspectStage(ctx1, final)
	require.True(t, ok)
	amdStage1 := stageDigestOf(t, ctx1, "localhost:5062/app", stageTags1, "linux-amd64")
	armStage1 := stageDigestOf(t, ctx1, "localhost:5062/app", stageTags1, "linux-arm64")
	require.NotEmpty(t, amdStage1)
	require.NotEmpty(t, armStage1)

	// unrelated, manually maintained tag must survive every later run.
	mustExecDocker(t, "buildx", "imagetools", "create",
		"-t", "localhost:5062/app:manual-tag",
		"localhost:5062/app@"+amdStage1)
	manualDigest1, ok := inspectStage(ctx1, "localhost:5062/app:manual-tag")
	require.True(t, ok)

	// run 2: nothing changed — zero builds, identical final index.
	resetLog(t, logPath)
	ctx2 := newCtx(t)
	require.NoError(t, Publish{}.Publish(ctx2))
	require.Equal(t, map[string]int{"linux/amd64": 0, "linux/arm64": 0}, platformBuildCounts(t, logPath))
	require.Len(t, createInvocations(t, logPath), 1)
	finalDigest2, ok := inspectStage(ctx2, final)
	require.True(t, ok)
	require.Equal(t, finalDigest1, finalDigest2, "final index must be identical on rerun")

	// run 3: arm64 content changes — only arm64 is rebuilt, amd64 reused.
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-arm64"), []byte("arm64-binary-v2-CHANGED"), 0o644))
	resetLog(t, logPath)
	ctx3 := newCtx(t)
	require.NoError(t, Publish{}.Publish(ctx3))
	require.Equal(t, map[string]int{"linux/amd64": 0, "linux/arm64": 1}, platformBuildCounts(t, logPath))
	require.Len(t, createInvocations(t, logPath), 1)

	tags3 := registryTagList(t, "5062", "app")
	require.Len(t, tags3, 2+1+3, "2 final tags, 1 manual tag, 3 staging tags (new arm64 content)")
	platformsOf(t, inspectIndex(t, final), "linux/amd64", "linux/arm64")

	// the amd64 staging tag and the manual tag are untouched.
	ctx4 := testctx.Wrap(t.Context())
	amdStage2 := stageDigestOf(t, ctx4, "localhost:5062/app", registryTagList(t, "5062", "app"), "linux-amd64")
	require.Equal(t, amdStage1, amdStage2)
	manualDigest2, ok := inspectStage(ctx4, "localhost:5062/app:manual-tag")
	require.True(t, ok)
	require.Equal(t, manualDigest1, manualDigest2, "manual tag must never change")
}

func TestResumeFailureConverges(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "registry images only available for windows")
	testlib.StartRegistry(t, "resume-fail-registry", "5063")

	work, _ := isolatedDockerContextTemp(t)
	require.NoError(t, os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(resumeDockerfile), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-amd64"), []byte("amd64-binary"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-arm64"), []byte("arm64-binary"), 0o644))

	logPath := filepath.Join(t.TempDir(), "docker.log")
	installDockerCountShim(t, t.TempDir(), logPath, true)

	newCtx := func(t *testing.T) *context.Context {
		t.Helper()
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			ProjectName: "resume",
			DockersV2: []config.DockerV2{{
				ID: "app", Dockerfile: "Dockerfile",
				Images:    []string{"localhost:5063/fail"},
				Tags:      []string{"v1"},
				Platforms: []string{"linux/amd64", "linux/arm64"},
				Resume:    "true",
				SBOM:      "true",
			}},
		}, testctx.WithVersion("1.0.0"), testctx.WithCurrentTag("v1.0.0"), testctx.WithSemver(1, 0, 0, ""))
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-amd64", Goos: "linux", Goarch: "amd64", Type: artifact.Binary})
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-arm64", Goos: "linux", Goarch: "arm64", Type: artifact.Binary})
		return ctx
	}

	// first run: arm64 is injected-failed (only after amd64 fully succeeds);
	// the final tag must not be created.
	require.Error(t, Publish{}.Publish(newCtx(t)))
	if _, ok := inspectStage(testctx.Wrap(t.Context()), "localhost:5063/fail:v1"); ok {
		t.Fatal("final tag must not exist while a platform failed")
	}
	stageTags := registryTagList(t, "5063", "fail")
	require.Len(t, stageTags, 1, "only the successful amd64 staging tag exists")
	require.Contains(t, stageTags[0], "linux-amd64-")

	// rerun: amd64 reused, arm64 rebuilt, full index promoted.
	require.NoError(t, os.Setenv("DOCKER_RESUME_TEST_FAIL_ARM64", ""))
	t.Cleanup(func() { _ = os.Unsetenv("DOCKER_RESUME_TEST_FAIL_ARM64") })
	resetLog(t, logPath)
	require.NoError(t, Publish{}.Publish(newCtx(t)))
	require.Equal(t, map[string]int{"linux/amd64": 0, "linux/arm64": 1}, platformBuildCounts(t, logPath))

	idx := inspectIndex(t, "localhost:5063/fail:v1")
	platformsOf(t, idx, "linux/amd64", "linux/arm64")
	require.True(t, hasSBOM(t, "localhost:5063/fail:v1"))
}

func TestResumeLegacyPaths(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "registry images only available for windows")
	testlib.StartRegistry(t, "resume-legacy-registry", "5064")

	work, _ := isolatedDockerContextTemp(t)
	require.NoError(t, os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(resumeDockerfile), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-amd64"), []byte("amd64-binary"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-arm64"), []byte("arm64-binary"), 0o644))

	logPath := filepath.Join(t.TempDir(), "docker.log")
	installDockerCountShim(t, t.TempDir(), logPath, false)

	t.Run("single platform direct push", func(t *testing.T) {
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			DockersV2: []config.DockerV2{{
				ID: "single", Dockerfile: "Dockerfile",
				Images:    []string{"localhost:5064/single"},
				Tags:      []string{"v1"},
				Platforms: []string{"linux/amd64"},
				Resume:    "true",
				SBOM:      "true",
			}},
		}, testctx.WithVersion("1.0.0"))
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-amd64", Goos: "linux", Goarch: "amd64", Type: artifact.Binary})
		require.NoError(t, Base{}.Default(ctx))
		require.NoError(t, Publish{}.Publish(ctx))

		tags := registryTagList(t, "5064", "single")
		require.Contains(t, tags, "v1")
		for _, tag := range tags {
			require.False(t, strings.HasPrefix(tag, stagingTagPrefix), "single platform must not use staging tags: %s", tag)
		}
	})

	t.Run("resume disabled keeps one-shot multi build", func(t *testing.T) {
		resetLog(t, logPath)
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			DockersV2: []config.DockerV2{{
				ID: "legacy", Dockerfile: "Dockerfile",
				Images:    []string{"localhost:5064/legacy"},
				Tags:      []string{"v1"},
				Platforms: []string{"linux/amd64", "linux/arm64"},
				Resume:    "false",
				SBOM:      "true",
			}},
		}, testctx.WithVersion("1.0.0"))
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-amd64", Goos: "linux", Goarch: "amd64", Type: artifact.Binary})
		ctx.Artifacts.Add(&artifact.Artifact{Name: "mybin", Path: "mybin-arm64", Goos: "linux", Goarch: "arm64", Type: artifact.Binary})
		require.NoError(t, Base{}.Default(ctx))
		require.NoError(t, Publish{}.Publish(ctx))

		require.Equal(t, map[string]int{"linux/amd64,linux/arm64": 1}, joinedPlatformBuilds(t, logPath))
		for _, tag := range registryTagList(t, "5064", "legacy") {
			require.False(t, strings.HasPrefix(tag, stagingTagPrefix))
		}
		require.Empty(t, createInvocations(t, logPath))
	})
}

// --- helpers ---

func platformsOf(t *testing.T, idx v1.IndexManifest, want ...string) {
	t.Helper()
	var got []string
	for _, desc := range idx.Manifests {
		if desc.Platform == nil || desc.Platform.Architecture == "unknown" {
			continue
		}
		got = append(got, desc.Platform.OS+"/"+desc.Platform.Architecture)
	}
	slices.Sort(got)
	want = append([]string(nil), want...)
	slices.Sort(want)
	require.Equal(t, want, got)
}

func manifestAnnotationsOf(t *testing.T, idx v1.IndexManifest, image, platform string) map[string]string {
	t.Helper()
	for _, desc := range idx.Manifests {
		if desc.Platform == nil || desc.Platform.OS+"/"+desc.Platform.Architecture != platform {
			continue
		}
		return inspectManifest(t, image+"@"+desc.Digest.String()).Annotations
	}
	t.Fatalf("platform %s not found", platform)
	return nil
}

func stageDigestOf(t *testing.T, ctx *context.Context, image string, tags []string, slugPart string) string {
	t.Helper()
	var matches []string
	for _, tag := range tags {
		if strings.Contains(tag, "-"+slugPart+"-") {
			matches = append(matches, tag)
		}
	}
	require.Len(t, matches, 1, "expected exactly one %s staging tag, got %v", slugPart, matches)
	digest, ok := inspectStage(ctx, image+":"+matches[0])
	require.True(t, ok)
	return digest
}

func registryTagList(t *testing.T, port, repo string) []string {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://localhost:%s/v2/%s/tags/list", port, repo))
	require.NoError(t, err)
	defer resp.Body.Close()
	bts, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var payload struct {
		Tags []string `json:"tags"`
	}
	require.NoError(t, json.Unmarshal(bts, &payload), "body: %s", string(bts))
	return payload.Tags
}

// installDockerCountShim puts a docker wrapper on PATH that logs builds and
// promotions to logPath and optionally fails arm64 builds (after amd64
// succeeds). All invocations are forwarded to the real docker binary.
func installDockerCountShim(t *testing.T, dir, logPath string, canFailArm64 bool) {
	t.Helper()
	real := realDockerPath(t, dir)
	amdDone := filepath.Join(filepath.Dir(logPath), "amd64.done")
	t.Setenv("DOCKER_RESUME_TEST_LOG", logPath)
	t.Setenv("DOCKER_RESUME_TEST_REAL", real)
	t.Setenv("DOCKER_RESUME_TEST_AMD_DONE", amdDone)
	if canFailArm64 {
		t.Setenv("DOCKER_RESUME_TEST_FAIL_ARM64", "1")
	}
	script := `#!/bin/sh
LOG="$DOCKER_RESUME_TEST_LOG"
if [ "$1" = "buildx" ] && [ "$2" = "build" ]; then
	plat=""
	prev=""
	for a in "$@"; do
		if [ "$prev" = "--platform" ]; then plat="$a"; fi
		prev="$a"
	done
	if [ "${DOCKER_RESUME_TEST_FAIL_ARM64:-}" = "1" ] && [ "$plat" = "linux/arm64" ]; then
		i=0
		while [ ! -f "$DOCKER_RESUME_TEST_AMD_DONE" ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done
		echo "FAIL|linux/arm64" >> "$LOG"
		echo "injected arm64 failure" >&2
		exit 1
	fi
	"$DOCKER_RESUME_TEST_REAL" "$@"
	rc=$?
	if [ $rc -eq 0 ]; then
		echo "BUILD|$plat" >> "$LOG"
		[ "$plat" = "linux/amd64" ] && : > "$DOCKER_RESUME_TEST_AMD_DONE"
	fi
	exit $rc
fi
if [ "$1" = "buildx" ] && [ "$2" = "imagetools" ] && [ "$3" = "create" ]; then
	echo "CREATE|" >> "$LOG"
fi
exec "$DOCKER_RESUME_TEST_REAL" "$@"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func realDockerPath(t *testing.T, excludeDir string) string {
	t.Helper()
	old := os.Getenv("PATH")
	defer os.Setenv("PATH", old)
	_ = os.Setenv("PATH", strings.ReplaceAll(old, excludeDir+string(os.PathListSeparator), ""))
	real, err := exec.LookPath("docker")
	require.NoError(t, err)
	return real
}

func resetLog(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0o644))
}

func platformBuildCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	out := map[string]int{"linux/amd64": 0, "linux/arm64": 0}
	for _, line := range readShimLog(t, path) {
		if platform, ok := strings.CutPrefix(line, "BUILD|"); ok {
			out[platform]++
		}
	}
	return out
}

func joinedPlatformBuilds(t *testing.T, path string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, line := range readShimLog(t, path) {
		if platform, ok := strings.CutPrefix(line, "BUILD|"); ok {
			out[platform]++
		}
	}
	return out
}

func createInvocations(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, line := range readShimLog(t, path) {
		if strings.HasPrefix(line, "CREATE|") {
			out = append(out, line)
		}
	}
	return out
}

func readShimLog(t *testing.T, path string) []string {
	t.Helper()
	bts, err := os.ReadFile(path)
	require.NoError(t, err)
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(bts)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func mustExecDocker(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker %s: %s", strings.Join(args, " "), string(out))
}
