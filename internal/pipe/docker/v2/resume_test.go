package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/internal/testlib"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
	"github.com/stretchr/testify/require"
)

// separator between recorded command args.
const recSep = "\x1f"

func TestReleaseKey(t *testing.T) {
	k1 := releaseKey("v1.0.0", []string{"latest", "v1.0.0"})
	require.Len(t, k1, fingerprintTagLen)
	require.Regexp(t, "^[0-9a-f]+$", k1)

	// deterministic, order independent and duplicate tolerant.
	require.Equal(t, k1, releaseKey("v1.0.0", []string{"v1.0.0", "latest"}))
	require.Equal(t, k1, releaseKey("v1.0.0", []string{"latest", "latest", "v1.0.0"}))

	// version and tag changes must show.
	require.NotEqual(t, k1, releaseKey("v1.0.1", []string{"latest", "v1.0.0"}))
	require.NotEqual(t, k1, releaseKey("v1.0.0", []string{"v1.0.0"}))
}

func TestStagingNameAndRef(t *testing.T) {
	name := stagingName("abc123", "linux/arm/v7", strings.Repeat("f", 64))
	require.Equal(t, "goreleaser-stage-abc123-linux-arm-v7-ffffffffffff", name)

	ref := stagingRef("localhost:5000/foo", "k", "linux/amd64", "aabbccddeeff00112233")
	require.Equal(t, "localhost:5000/foo:goreleaser-stage-k-linux-amd64-aabbccddeeff", ref)

	// bare image names without a registry keep working.
	require.Equal(t, "image:goreleaser-stage-k-linux-amd64-aabbccddeeff",
		stagingRef("image", "k", "linux/amd64", "aabbccddeeff00112233"))

	// tags only contain legal characters.
	require.Regexp(t, `^[A-Za-z0-9_][A-Za-z0-9_.-]+$`, name)
}

func TestDedupe(t *testing.T) {
	require.Equal(t,
		[]string{"linux/amd64", "linux/arm64"},
		dedupe([]string{"linux/amd64", "linux/arm64", "linux/amd64"}),
	)
}

func TestContentFingerprint(t *testing.T) {
	mkCtx := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range files {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
		}
		return dir
	}
	input := fingerprintInput{
		platform:    "linux/amd64",
		sbom:        true,
		labels:      map[string]string{"a": "b"},
		annotations: map[string]string{"index:k": "v"},
		buildArgs:   map[string]string{"FOO": "bar"},
		flags:       []string{"--ulimit=10"},
		baseName:    "alpine:3.20",
		baseDigest:  "sha256:abc",
	}

	files := map[string]string{
		"Dockerfile":          "FROM scratch\n",
		"linux/amd64/mybin":   "binary",
		"testdata/extra.conf": "extra",
	}

	dir1 := mkCtx(t, files)
	dir2 := mkCtx(t, map[string]string{
		"testdata/extra.conf": "extra",
		"linux/amd64/mybin":   "binary",
		"Dockerfile":          "FROM scratch\n",
	})
	fp1, err := contentFingerprint(dir1, input)
	require.NoError(t, err)
	fp2, err := contentFingerprint(dir2, input)
	require.NoError(t, err)
	require.Len(t, fp1, 64)
	require.Equal(t, fp1, fp2, "identical content, different paths/order must hash equal")

	changes := []struct {
		name  string
		dir   map[string]string
		input fingerprintInput
	}{
		{"file content", map[string]string{"Dockerfile": "FROM scratch\n", "linux/amd64/mybin": "changed"}, input},
		{"file path", map[string]string{"Dockerfile": "FROM scratch\n", "linux/amd64/other": "binary"}, input},
		{"platform", files, func() fingerprintInput { i := input; i.platform = "linux/arm64"; return i }()},
		{"sbom", files, func() fingerprintInput { i := input; i.sbom = false; return i }()},
		{"label", files, func() fingerprintInput { i := input; i.labels = map[string]string{"a": "c"}; return i }()},
		{"annotation", files, func() fingerprintInput { i := input; i.annotations = map[string]string{"index:k": "w"}; return i }()},
		{"buildarg", files, func() fingerprintInput { i := input; i.buildArgs = map[string]string{"FOO": "baz"}; return i }()},
		{"flag", files, func() fingerprintInput { i := input; i.flags = []string{"--ulimit=20"}; return i }()},
		{"base digest", files, func() fingerprintInput { i := input; i.baseDigest = "sha256:def"; return i }()},
	}
	for _, tt := range changes {
		t.Run(tt.name, func(t *testing.T) {
			dir := mkCtx(t, tt.dir)
			fp, err := contentFingerprint(dir, tt.input)
			require.NoError(t, err)
			require.NotEqual(t, fp1, fp)
		})
	}
}

func TestBuildAnnotations(t *testing.T) {
	ann := map[string]string{
		"org.opencontainers.image.description":             "d",
		"index:org.opencontainers.image.description":       "d2",
		"index,manifest:org.opencontainers.image.revision": "abc",
		"manifest[linux/amd64]:com.example.arch":           "amd64",
		"manifest[linux/arm64]:com.example.arch":           "arm64",
		"manifest-descriptor:md":                           "1",
		"index-descriptor:id":                              "9",
		"weirdscope:x":                                     "y",
	}
	got := buildAnnotations(ann, "linux/amd64")
	// order follows the raw annotation keys: index,manifest sorts first, then
	// manifest-descriptor and manifest[qualifier], unknown scopes last.
	require.Equal(t, []string{
		"--annotation", "manifest:org.opencontainers.image.revision=abc",
		"--annotation", "manifest-descriptor:md=1",
		"--annotation", "manifest[linux/amd64]:com.example.arch=amd64",
		// unknown scopes are passed through unchanged.
		"--annotation", "weirdscope:x=y",
	}, got)

	gotArm := buildAnnotations(ann, "linux/arm64")
	require.Contains(t, joinedPairs(gotArm), "manifest[linux/arm64]:com.example.arch=arm64")
	for _, g := range gotArm {
		require.NotContains(t, g, "linux/amd64")
	}
	for _, g := range got {
		require.NotContains(t, g, "index-descriptor")
	}
}

func TestCreateAnnotations(t *testing.T) {
	ann := map[string]string{
		"org.opencontainers.image.description":             "d",
		"index:org.opencontainers.image.source":            "src",
		"index,manifest:org.opencontainers.image.revision": "abc",
		"manifest:m":          "1",
		"index-descriptor:id": "9",
		"weirdscope:x":        "y",
	}
	// order follows the raw, pre-scope annotation keys.
	require.Equal(t, []string{
		"--annotation", "index:org.opencontainers.image.revision=abc",
		"--annotation", "index:org.opencontainers.image.source=src",
		"--annotation", "index:org.opencontainers.image.description=d",
	}, createAnnotations(ann))
}

func TestUseResumablePublish(t *testing.T) {
	for name, tt := range map[string]struct {
		cfg      config.DockerV2
		expected bool
	}{
		"multi platform default": {
			cfg:      config.DockerV2{Resume: "true", Platforms: []string{"linux/amd64", "linux/arm64"}},
			expected: true,
		},
		"empty default still on after defaults": {
			cfg:      withResumeDefaults(t, config.DockerV2{Platforms: []string{"linux/amd64", "linux/arm64"}}),
			expected: true,
		},
		"single platform": {
			cfg:      config.DockerV2{Resume: "true", Platforms: []string{"linux/amd64"}},
			expected: false,
		},
		"disabled": {
			cfg:      config.DockerV2{Resume: "false", Platforms: []string{"linux/amd64", "linux/arm64"}},
			expected: false,
		},
		"duplicated platform": {
			cfg:      config.DockerV2{Resume: "true", Platforms: []string{"linux/amd64", "linux/amd64"}},
			expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := testctx.Wrap(t.Context())
			got, err := useResumablePublish(ctx, tt.cfg)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}

	t.Run("bad template", func(t *testing.T) {
		ctx := testctx.Wrap(t.Context())
		_, err := useResumablePublish(ctx, config.DockerV2{Resume: "{{ .Nope }}"})
		require.Error(t, err)
	})
}

func withResumeDefaults(t *testing.T, d config.DockerV2) config.DockerV2 {
	t.Helper()
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{DockersV2: []config.DockerV2{d}})
	require.NoError(t, Base{}.Default(ctx))
	return ctx.Config.DockersV2[0]
}

func TestInspectStage(t *testing.T) {
	state := t.TempDir()
	installResumeFakeDocker(t, t.TempDir(), state)
	ctx := testctx.Wrap(t.Context())

	t.Run("hit", func(t *testing.T) {
		ref := "localhost:5000/app:hit"
		writeStageState(t, state, ref, `{"mediaType":"application/vnd.oci.image.index.v1+json"}`)
		digest, ok := inspectStage(ctx, ref)
		require.True(t, ok)
		require.True(t, strings.HasPrefix(digest, "sha256:"))
	})

	t.Run("miss", func(t *testing.T) {
		digest, ok := inspectStage(ctx, "localhost:5000/app:missing")
		require.False(t, ok)
		require.Empty(t, digest)
	})
}

func TestResolveDockerDisabled(t *testing.T) {
	ctx := testctx.Wrap(t.Context())
	_, err := resolveDocker(ctx, config.DockerV2{
		Disable:   "true",
		Resume:    "true",
		Platforms: []string{"linux/amd64", "linux/arm64"},
		Images:    []string{"img"},
		Tags:      []string{"v1"},
	})
	testlib.AssertSkipped(t, err)

	_, err = resolveDocker(ctx, config.DockerV2{Disable: "{{ .Nope }}"})
	require.Error(t, err)
}

func TestPromoteRequiresAllDigests(t *testing.T) {
	ctx := testctx.Wrap(t.Context())
	rd := resolvedDocker{cfg: config.DockerV2{ID: "x"}}
	plan := releasePlan{
		key:       "k",
		images:    []string{"img"},
		tags:      []string{"v1"},
		platforms: []string{"linux/amd64", "linux/arm64"},
	}
	results := []platformResult{{
		platform:    "linux/amd64",
		fingerprint: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		digests:     map[string]string{"img": "sha256:aaa"},
	}}
	err := promote(ctx, rd, plan, results, nil)
	require.ErrorContains(t, err, "missing digest for platform linux/arm64")
}

// --- end-to-end orchestration with the stateful fake docker ---

type resumeEnv struct {
	ctx     *context.Context
	workdir string
	state   string
	rd      resolvedDocker
	unfail  func()
}

func TestPublishResumableFirstRun(t *testing.T) {
	env := setupResumeEnv(t, "")
	require.NoError(t, publishResumable(env.ctx, env.rd))

	builds := env.invocations("build")
	require.Len(t, builds, 2, "one staging build per platform")
	for _, line := range builds {
		fields := strings.Split(line, recSep)
		require.Contains(t, fields, "--push")
		require.Contains(t, fields, "--platform")
		require.Equal(t, 2, countValues(fields, "-t"), "pushed to both image repos")
		requireTagPrefix(t, fields, stagingTagPrefix)
		require.NotContains(t, fields, "localhost:5060/foo:v1.0.0")
	}
	amdBuild := findBuild(builds, "linux/amd64")
	armBuild := findBuild(builds, "linux/arm64")
	require.Contains(t, amdBuild, recSep+"manifest[linux/amd64]:arch-only=yes"+recSep)
	require.NotContains(t, amdBuild, "manifest[linux/arm64]")
	require.NotContains(t, armBuild, "arch-only=yes")
	for _, b := range builds {
		require.Contains(t, b, recSep+"manifest:m-key=mv"+recSep)
	}

	creates := env.invocations("create")
	require.Len(t, creates, 2, "one imagetools create per image repo")
	repos := map[string][]string{}
	for _, line := range creates {
		fields := strings.Split(line, recSep)
		tags := valuesFor(fields, "-t")
		require.Len(t, tags, 2)
		repo := strings.TrimSuffix(tags[0], ":v1.0.0")
		require.Equal(t, repo+":latest", tags[1])
		repos[repo] = tags
		require.Equal(t, 2, countStringsContaining(fields, "@sha256:"), "one digest source per platform")
		require.Contains(t, fields, "index:index-key=iv")
	}
	var repoNames []string
	for repo := range repos {
		repoNames = append(repoNames, repo)
	}
	slices.Sort(repoNames)
	require.Equal(t, []string{"localhost:5060/bar", "localhost:5060/foo"}, repoNames)

	var names []string
	for _, art := range env.ctx.Artifacts.Filter(artifact.ByType(artifact.DockerImageV2)).List() {
		names = append(names, art.Name)
		require.NotEmpty(t, artifact.ExtraOr(*art, artifact.ExtraDigest, ""))
		require.Equal(t, []string{"linux/amd64", "linux/arm64"},
			artifact.ExtraOr(*art, ExtraPlatforms, []string{}))
	}
	slices.Sort(names)
	require.Equal(t, []string{
		"localhost:5060/bar:latest",
		"localhost:5060/bar:v1.0.0",
		"localhost:5060/foo:latest",
		"localhost:5060/foo:v1.0.0",
	}, names)
}

func TestPublishResumableReusesEverythingOnRerun(t *testing.T) {
	env := setupResumeEnv(t, "")
	require.NoError(t, publishResumable(env.ctx, env.rd))
	firstBuilds := len(env.invocations("build"))
	firstCreates := len(env.invocations("create"))

	require.NoError(t, publishResumable(env.ctx, env.rd))
	require.Len(t, env.invocations("build"), firstBuilds, "no platform rebuilt when nothing changed")
	require.Len(t, env.invocations("create"), firstCreates*2, "promotion still re-runs and is idempotent")
}

func TestPublishResumableRebuildsOnlyChangedPlatform(t *testing.T) {
	env := setupResumeEnv(t, "")
	require.NoError(t, publishResumable(env.ctx, env.rd))
	firstBuilds := len(env.invocations("build"))

	// change only the arm64 binary.
	require.NoError(t, os.WriteFile(filepath.Join(env.workdir, "mybin-arm64"), []byte("brand-new-arm64-content"), 0o644))
	require.NoError(t, publishResumable(env.ctx, env.rd))

	builds := env.invocations("build")
	require.Len(t, builds, firstBuilds+1)
	require.Equal(t, "linux/arm64", valueFor(strings.Split(builds[len(builds)-1], recSep), "--platform"))
}

func TestPublishResumableFailureAndConvergingRerun(t *testing.T) {
	env := setupResumeEnv(t, "linux/arm64")
	require.Error(t, publishResumable(env.ctx, env.rd))
	require.Empty(t, env.invocations("create"), "no promotion while any platform is missing")
	require.Empty(t, env.ctx.Artifacts.Filter(artifact.ByType(artifact.DockerImageV2)).List())
	require.Equal(t, 1, countPlatformBuilds(env.invocations("build"), "linux/amd64"))
	require.Equal(t, 1, countPlatformBuilds(env.invocations("build"), "linux/arm64"))

	// truncate invocation logs to measure the rerun in isolation.
	_ = os.Remove(logFile(env.state, "build"))
	_ = os.Remove(logFile(env.state, "create"))
	env.unfail()
	require.NoError(t, publishResumable(env.ctx, env.rd))
	require.Len(t, env.invocations("create"), 2)
	// amd64 is reused (zero rebuilds), arm64 built once in the rerun.
	require.Equal(t, 0, countPlatformBuilds(env.invocations("build"), "linux/amd64"))
	require.Equal(t, 1, countPlatformBuilds(env.invocations("build"), "linux/arm64"))
}

func TestPublishBranchesLegacyPath(t *testing.T) {
	for name, tt := range map[string]struct {
		platforms []string
		artifacts []string
		resume    string
	}{
		"single platform": {
			platforms: []string{"linux/amd64"},
			artifacts: []string{"mybin-amd64"},
			resume:    "true",
		},
		"resume disabled": {
			platforms: []string{"linux/amd64", "linux/arm64"},
			artifacts: []string{"mybin-amd64", "mybin-arm64"},
			resume:    "false",
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			installResumeFakeDocker(t, t.TempDir(), state)
			work, _ := isolatedDockerContextTemp(t)
			require.NoError(t, os.WriteFile(filepath.Join(work, "Dockerfile"), []byte("FROM scratch\n"), 0o644))
			for _, arch := range []string{"amd64", "arm64"} {
				require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-"+arch), []byte("binary-"+arch), 0o644))
			}

			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				DockersV2: []config.DockerV2{{
					ID: "x", Dockerfile: "Dockerfile",
					Images:    []string{"localhost:5060/foo"},
					Tags:      []string{"v1"},
					Platforms: tt.platforms,
					Resume:    tt.resume,
					SBOM:      "true",
				}},
			})
			for _, arch := range []string{"amd64", "arm64"} {
				ctx.Artifacts.Add(&artifact.Artifact{
					Name: "mybin", Path: "mybin-" + arch, Goos: "linux", Goarch: arch, Type: artifact.Binary,
				})
			}
			require.NoError(t, Base{}.Default(ctx))
			require.NoError(t, Publish{}.Publish(ctx))

			require.Empty(t, readInvocationLog(t, state, "inspect"), "no stage inspection in legacy path")
			require.Empty(t, readInvocationLog(t, state, "create"), "no imagetools create in legacy path")
			builds := readInvocationLog(t, state, "build")
			require.Len(t, builds, 1)
			require.NotContains(t, builds[0], stagingTagPrefix)
			require.Contains(t, builds[0], recSep+"localhost:5060/foo:v1"+recSep)
		})
	}
}

func setupResumeEnv(t *testing.T, failPlatform string) resumeEnv {
	t.Helper()
	state := t.TempDir()
	installResumeFakeDocker(t, t.TempDir(), state)
	work, _ := isolatedDockerContextTemp(t)

	require.NoError(t, os.WriteFile(filepath.Join(work, "Dockerfile"), []byte("FROM scratch\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-amd64"), []byte("amd64-binary"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(work, "mybin-arm64"), []byte("arm64-binary"), 0o644))

	ctx := testctx.Wrap(t.Context())
	// deterministic platform order: amd64 completes fully before arm64 can
	// fail, matching the "platform A succeeded, platform B failed" scenario.
	ctx.Parallelism = 1
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "mybin", Path: "mybin-amd64", Goos: "linux", Goarch: "amd64", Type: artifact.Binary,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "mybin", Path: "mybin-arm64", Goos: "linux", Goarch: "arm64", Type: artifact.Binary,
	})

	rd, err := resolveDocker(ctx, config.DockerV2{
		ID:         "myimg",
		Dockerfile: "Dockerfile",
		Images:     []string{"localhost:5060/foo", "localhost:5060/bar"},
		Tags:       []string{"v1.0.0", "latest"},
		Platforms:  []string{"linux/amd64", "linux/arm64"},
		Resume:     "true",
		SBOM:       "true",
		Labels:     map[string]string{"l": "v"},
		Annotations: map[string]string{
			"index:index-key":                 "iv",
			"manifest:m-key":                  "mv",
			"manifest[linux/amd64]:arch-only": "yes",
		},
		BuildArgs: map[string]string{"FOO": "bar"},
	})
	require.NoError(t, err)

	failFlag := filepath.Join(state, "fail-platform")
	if failPlatform != "" {
		require.NoError(t, os.WriteFile(failFlag, []byte(failPlatform), 0o644))
	}
	return resumeEnv{
		ctx:     ctx,
		workdir: work,
		state:   state,
		rd:      rd,
		unfail: func() {
			_ = os.Remove(failFlag)
		},
	}
}

func (e resumeEnv) invocations(kind string) []string {
	return readInvocationLog(nil, e.state, kind)
}

// --- fake docker helpers ---

func installResumeFakeDocker(t *testing.T, dir, state string) {
	t.Helper()
	t.Setenv("DOCKER_RESUME_STATE", state)
	t.Setenv("GO_WANT_DOCKER_V2_RESUME_HELPER", "1")
	script := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=TestDockerV2ResumeCommandHelper -- \"$@\"\n", os.Args[0])
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755))
	if testlib.IsWindows() {
		script := fmt.Sprintf("@echo off\r\n%q -test.run=TestDockerV2ResumeCommandHelper -- %%*\r\n", os.Args[0])
		require.NoError(t, os.WriteFile(filepath.Join(dir, "docker.bat"), []byte(script), 0o755))
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func stageFile(state, ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return filepath.Join(state, "stages", hex.EncodeToString(sum[:]))
}

func writeStageState(t *testing.T, state, ref, raw string) {
	t.Helper()
	require.NoError(t, putStageState(state, ref, raw))
}

func putStageState(state, ref, raw string) error {
	p := stageFile(state, ref)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(raw), 0o644)
}

func logFile(state, kind string) string {
	return filepath.Join(state, "logs", kind)
}

func readInvocationLog(t *testing.T, state, kind string) []string {
	bts, err := os.ReadFile(logFile(state, kind))
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(bts), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func appendInvocation(state, kind string, args []string) error {
	if err := os.MkdirAll(filepath.Join(state, "logs"), 0o755); err != nil {
		return err
	}
	line := strings.Join(args, recSep) + "\n"
	f, err := os.OpenFile(logFile(state, kind), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func fakeDigest(parts []string) string {
	sorted := slices.Clone(parts)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "|")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func flagValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func countValues(args []string, flag string) int {
	var n int
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			n++
		}
	}
	return n
}

func valuesFor(args []string, flag string) []string {
	var out []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

func valueFor(args []string, flag string) string {
	v, _ := flagValue(args, flag)
	return v
}

func countStringsContaining(args []string, substr string) int {
	var n int
	for _, a := range args {
		if strings.Contains(a, substr) {
			n++
		}
	}
	return n
}

func joinedPairs(flags []string) string {
	return strings.Join(flags, " ")
}

func findBuild(lines []string, platform string) string {
	for _, line := range lines {
		if valueFor(strings.Split(line, recSep), "--platform") == platform {
			return line
		}
	}
	return ""
}

func countPlatformBuilds(lines []string, platform string) int {
	var n int
	for _, line := range lines {
		if valueFor(strings.Split(line, recSep), "--platform") == platform {
			n++
		}
	}
	return n
}

func requireTagPrefix(t *testing.T, fields []string, prefix string) {
	t.Helper()
	for i, f := range fields {
		if f == "-t" && i+1 < len(fields) {
			tag := fields[i+1]
			idx := strings.LastIndex(tag, ":")
			require.NotEqual(t, -1, idx)
			require.True(t, strings.HasPrefix(tag[idx+1:], prefix), "tag %q should use the staging prefix", tag)
		}
	}
}

// TestDockerV2ResumeCommandHelper is the re-executed fake docker binary used
// by the resume tests.
func TestDockerV2ResumeCommandHelper(t *testing.T) {
	if os.Getenv("GO_WANT_DOCKER_V2_RESUME_HELPER") != "1" {
		return
	}
	state := os.Getenv("DOCKER_RESUME_STATE")

	args := os.Args[1:]
	if i := slices.Index(args, "--"); i >= 0 {
		args = args[i+1:]
	}
	// args: buildx <sub> ...
	if len(args) < 2 || args[0] != "buildx" {
		fmt.Fprintln(os.Stderr, "fake docker: unexpected args:", strings.Join(args, " "))
		os.Exit(1)
	}
	sub, rest := args[1], args[2:]
	if err := runFakeDocker(state, sub, rest); err != nil {
		fmt.Fprintln(os.Stderr, "fake docker error:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runFakeDocker(state, sub string, args []string) error {
	switch sub {
	case "build":
		return fakeBuild(state, args)
	case "imagetools":
		if len(args) == 0 {
			return fmt.Errorf("missing imagetools action")
		}
		action, a := args[0], args[1:]
		if err := appendInvocation(state, action, a); err != nil {
			return err
		}
		switch action {
		case "inspect":
			return fakeInspect(state, a)
		case "create":
			return fakeCreate(state, a)
		default:
			return fmt.Errorf("unexpected imagetools action %q", action)
		}
	default:
		// e.g. buildx inspect during health checks: do nothing.
		return nil
	}
}

func fakeBuild(state string, args []string) error {
	if err := appendInvocation(state, "build", args); err != nil {
		return err
	}
	platform := valueFor(args, "--platform")
	if bts, err := os.ReadFile(filepath.Join(state, "fail-platform")); err == nil && string(bts) == platform {
		return fmt.Errorf("fake build failure for %s", platform)
	}
	targets := valuesFor(args, "-t")

	// write the metadata file buildx would produce in the working directory.
	meta := map[string]any{
		"containerimage.digest": fakeDigest(targets),
	}
	bts, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if err := os.WriteFile("metadata.json", bts, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile("id.txt", []byte(fakeDigest(targets)), 0o644); err != nil {
		return err
	}

	// publish: make every target tag resolvable.
	for _, ref := range targets {
		raw := fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","_ref":%q}`, ref)
		if err := putStageState(state, ref, raw); err != nil {
			return err
		}
	}
	return nil
}

func fakeInspect(state string, args []string) error {
	raw, ref := false, ""
	for i, a := range args {
		if a == "--raw" {
			raw = true
		}
		if a == "--raw" && i+1 < len(args) {
			ref = args[i+1]
		}
	}
	if !raw || ref == "" {
		return fmt.Errorf("inspect: unexpected args %v", args)
	}
	bts, err := os.ReadFile(stageFile(state, ref))
	if err != nil {
		return fmt.Errorf("ERROR: %s: not found", ref)
	}
	fmt.Print(string(bts))
	return nil
}

func fakeCreate(state string, args []string) error {
	metaFile := ""
	var sources []string
	for i := 0; i < len(args); i++ {
		switch {
		case strings.HasPrefix(args[i], "--metadata-file="):
			metaFile = strings.TrimPrefix(args[i], "--metadata-file=")
		case args[i] == "-t" || args[i] == "--annotation":
			i++ // skip value
		default:
			if !strings.HasPrefix(args[i], "-") {
				sources = append(sources, args[i])
			}
		}
	}
	if metaFile == "" {
		return fmt.Errorf("create: missing metadata file")
	}
	meta := map[string]any{
		"containerimage.descriptor": map[string]any{
			"mediaType": "application/vnd.oci.image.index.v1+json",
			"digest":    fakeDigest(sources),
			"size":      123,
		},
	}
	bts, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(metaFile, bts, 0o644)
}
