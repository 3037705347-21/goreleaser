package dist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	ctx := testctx.Wrap(t.Context())
	require.NoError(t, Pipe{}.Default(ctx))
	require.Equal(t, "dist", ctx.Config.Dist)
}

func TestDistDoesNotExist(t *testing.T) {
	folder := t.TempDir()
	dist := filepath.Join(folder, "dist")
	require.NoError(t, Pipe{}.Run(testctx.WrapWithCfg(t.Context(), config.Project{Dist: dist})))
}

func TestPopulatedDistExists(t *testing.T) {
	folder := t.TempDir()
	dist := filepath.Join(folder, "dist")
	require.NoError(t, os.Mkdir(dist, 0o755))
	f, err := os.Create(filepath.Join(dist, "mybin"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{Dist: dist})
	require.Error(t, Pipe{}.Run(ctx))
	require.NoError(t, CleanPipe{}.Run(ctx))
	require.NoError(t, Pipe{}.Run(ctx))
	_, err = os.Stat(dist)
	require.False(t, os.IsExist(err))
}

func TestEmptyDistExists(t *testing.T) {
	folder := t.TempDir()
	dist := filepath.Join(folder, "dist")
	require.NoError(t, os.Mkdir(dist, 0o755))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{Dist: dist})
	require.NoError(t, Pipe{}.Run(ctx))
	_, err := os.Stat(dist)
	require.False(t, os.IsNotExist(err))
}

func TestString(t *testing.T) {
	require.NotEmpty(t, Pipe{}.String())
	require.NotEmpty(t, CleanPipe{}.String())
}

func TestCleanSkip(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		require.True(t, CleanPipe{}.Skip(testctx.Wrap(t.Context())))
	})
	t.Run("don't skip", func(t *testing.T) {
		require.False(t, CleanPipe{}.Skip(testctx.Wrap(t.Context(), func(ctx *context.Context) {
			ctx.Clean = true
		})))
	})
}

func TestCleanSetDist(t *testing.T) {
	ctx := testctx.Wrap(t.Context())
	require.NoError(t, CleanPipe{}.Run(ctx))
	require.Equal(t, "dist", ctx.Config.Dist)
}

func writeResumeState(t *testing.T, dist, version string, arts []*artifact.Artifact) {
	t.Helper()
	meta, err := json.Marshal(map[string]string{
		"project_name": "foo",
		"version":      version,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dist, "metadata.json"), meta, 0o644))

	manifest, err := json.Marshal(arts)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dist, "artifacts.json"), manifest, 0o644))
}

func TestPopulatedResumesSameVersion(t *testing.T) {
	folder := t.TempDir()
	dist := filepath.Join(folder, "dist")
	require.NoError(t, os.Mkdir(dist, 0o755))

	binPath := filepath.Join(dist, "foo_linux_amd64_v1", "foo")
	require.NoError(t, os.MkdirAll(filepath.Dir(binPath), 0o755))
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dist, "manual.txt"), []byte("manual"), 0o644))

	writeResumeState(t, dist, "1.0.0", []*artifact.Artifact{{
		Name:   "foo",
		Path:   binPath,
		Type:   artifact.Binary,
		Target: "linux_amd64_v1",
		Extra: map[string]any{
			artifact.ExtraID: "foo",
		},
	}})

	cfg := config.Project{
		Dist: dist,
		Builds: []config.Build{{
			ID:      "foo",
			Targets: []string{"linux_amd64_v1", "linux_arm64_v8.0"},
		}},
	}
	ctx := testctx.WrapWithCfg(t.Context(), cfg, testctx.WithVersion("1.0.0"))
	require.NoError(t, Pipe{}.Run(ctx))
	require.True(t, ctx.Resume)

	require.FileExists(t, binPath)
	require.FileExists(t, filepath.Join(dist, "manual.txt"))
	require.Len(t, ctx.Artifacts.List(), 1)

	// the target removed from the configuration is cleaned on finalize,
	// but an immediate re-run of the ensuring pipe stays idempotent
	require.NoError(t, Pipe{}.Run(ctx))
}

func TestPopulatedDifferentVersionStillErrors(t *testing.T) {
	folder := t.TempDir()
	dist := filepath.Join(folder, "dist")
	require.NoError(t, os.Mkdir(dist, 0o755))
	binPath := filepath.Join(dist, "foo_linux_amd64_v1", "foo")
	require.NoError(t, os.MkdirAll(filepath.Dir(binPath), 0o755))
	require.NoError(t, os.WriteFile(binPath, []byte("binary"), 0o755))
	writeResumeState(t, dist, "0.9.0", []*artifact.Artifact{{
		Name:   "foo",
		Path:   binPath,
		Type:   artifact.Binary,
		Target: "linux_amd64_v1",
		Extra: map[string]any{
			artifact.ExtraID: "foo",
		},
	}})

	ctx := testctx.WrapWithCfg(t.Context(), config.Project{Dist: dist}, testctx.WithVersion("1.0.0"))
	require.Error(t, Pipe{}.Run(ctx))
	require.False(t, ctx.Resume)
}
