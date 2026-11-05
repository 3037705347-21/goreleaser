package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/pipe/changelog"
	"github.com/goreleaser/goreleaser/v2/internal/skips"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
	"github.com/stretchr/testify/require"
)

func TestReleaseAutoSnapshot(t *testing.T) {
	// --auto-snapshot on a clean tree does not imply --snapshot, so this also
	// covers a release that runs the validation pipe.
	t.Run("clean", func(t *testing.T) {
		setup(t)
		cmd := newReleaseCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--skip=publish", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		require.FileExists(t, "dist/fake_0.0.2_checksums.txt", "should have created checksums when run with --snapshot")
	})

	t.Run("dirty", func(t *testing.T) {
		setup(t)
		createFile(t, "foo", "force dirty tree")
		cmd := newReleaseCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--skip=publish", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_0.0.2-SNAPSHOT-*_checksums.txt")
		require.NoError(t, err)
		require.Len(t, matches, 1, "should have implied --snapshot")
	})
}

func TestReleaseAutoSnapshotWithProConfig(t *testing.T) {
	t.Run("explicit snapshot", func(t *testing.T) {
		setupPro(t)
		cmd := newReleaseCmd()
		cmd.cmd.SetArgs([]string{"--snapshot", "--skip=publish", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_0.0.2-SNAPSHOT-*_checksums.txt")
		require.NoError(t, err)
		require.Len(t, matches, 1)
	})

	t.Run("dirty automatic snapshot", func(t *testing.T) {
		setupPro(t)
		createFile(t, "foo", "force dirty tree")
		cmd := newReleaseCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--skip=publish", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_0.0.2-SNAPSHOT-*_checksums.txt")
		require.NoError(t, err)
		require.Len(t, matches, 1)
	})

	t.Run("clean automatic snapshot", func(t *testing.T) {
		setupPro(t)
		cmd := newReleaseCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--skip=publish", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.ErrorIs(t, cmd.cmd.Execute(), config.ErrProConfig)
	})
}

func TestReleaseInvalidConfig(t *testing.T) {
	mktmp(t)
	createFile(t, "goreleaser.yml", "foo: bar\nversion: 2")
	cmd := newReleaseCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
	require.EqualError(t, cmd.cmd.Execute(), "yaml: unmarshal errors:\n  line 1: field foo not found in type config.Project")
}

func TestReleaseBrokenProject(t *testing.T) {
	setup(t)
	createFile(t, "main.go", "not a valid go file")
	cmd := newReleaseCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=1m", "--parallelism=2"})
	require.ErrorContains(t, cmd.cmd.Execute(), "failed to parse dir: .: main.go:1:1: expected 'package', found not")
}

func TestReleaseFlags(t *testing.T) {
	setup := func(tb testing.TB, opts releaseOpts) *context.Context {
		tb.Helper()
		ctx := testctx.Wrap(tb.Context())
		require.NoError(tb, setupReleaseContext(ctx, opts))
		return ctx
	}

	t.Run("draft", func(t *testing.T) {
		t.Run("not set", func(t *testing.T) {
			ctx := setup(t, releaseOpts{})
			require.False(t, ctx.Config.Release.Draft)
		})

		t.Run("set via flag", func(t *testing.T) {
			ctx := setup(t, releaseOpts{
				draft: true,
			})
			require.True(t, ctx.Config.Release.Draft)
		})

		t.Run("set in config", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Release: config.Release{
					Draft: true,
				},
			})

			require.NoError(t, setupReleaseContext(ctx, releaseOpts{}))
			require.True(t, ctx.Config.Release.Draft)
		})
	})

	t.Run("action", func(t *testing.T) {
		ctx := setup(t, releaseOpts{})
		require.Equal(t, context.ActionRelease, ctx.Action)
	})

	t.Run("snapshot", func(t *testing.T) {
		ctx := setup(t, releaseOpts{
			snapshot: true,
		})
		require.True(t, ctx.Snapshot)
		requireAll(t, ctx, skips.Publish, skips.Validate, skips.Announce)
	})

	t.Run("skips", func(t *testing.T) {
		ctx := setup(t, releaseOpts{
			skips: []string{
				string(skips.Publish),
				string(skips.Sign),
				string(skips.Validate),
			},
		})

		requireAll(t, ctx, skips.Sign, skips.Publish, skips.Validate, skips.Announce)
	})

	t.Run("skip changelog", func(t *testing.T) {
		for name, opts := range map[string]releaseOpts{
			"default": {
				skips: []string{string(skips.Changelog)},
			},
			"with release notes": {
				skips:            []string{string(skips.Changelog)},
				releaseNotesFile: "notes.md",
			},
		} {
			t.Run(name, func(t *testing.T) {
				ctx := setup(t, opts)
				requireAll(t, ctx, skips.Changelog)

				skip, err := changelog.Pipe{}.Skip(ctx)
				require.NoError(t, err)
				require.True(t, skip)
			})
		}
	})

	t.Run("parallelism", func(t *testing.T) {
		require.Equal(t, 1, setup(t, releaseOpts{
			parallelism: 1,
		}).Parallelism)
	})

	t.Run("notes", func(t *testing.T) {
		notes := "foo.md"
		header := "header.md"
		footer := "footer.md"
		ctx := setup(t, releaseOpts{
			releaseNotesFile:  notes,
			releaseHeaderFile: header,
			releaseFooterFile: footer,
		})
		require.Equal(t, notes, ctx.ReleaseNotesFile)
		require.Equal(t, header, ctx.ReleaseHeaderFile)
		require.Equal(t, footer, ctx.ReleaseFooterFile)
	})

	t.Run("templated notes", func(t *testing.T) {
		notes := "foo.md"
		header := "header.md"
		footer := "footer.md"
		ctx := setup(t, releaseOpts{
			releaseNotesTmpl:  notes,
			releaseHeaderTmpl: header,
			releaseFooterTmpl: footer,
		})
		require.Equal(t, notes, ctx.ReleaseNotesTmpl)
		require.Equal(t, header, ctx.ReleaseHeaderTmpl)
		require.Equal(t, footer, ctx.ReleaseFooterTmpl)
	})

	t.Run("rm dist", func(t *testing.T) {
		require.True(t, setup(t, releaseOpts{
			clean: true,
		}).Clean)
	})
}

func TestReleaseResumeAfterInterruption(t *testing.T) {
	setup(t)

	args := []string{"--snapshot", "--skip=publish", "--timeout=2m", "--parallelism=2", "--deprecated"}

	// first, a full snapshot release (build + archive + checksums)
	cmd := newReleaseCmd()
	cmd.cmd.SetArgs(args)
	require.NoError(t, cmd.cmd.Execute())

	matches, err := filepath.Glob("./dist/*_linux_amd64.tar")
	require.NoError(t, err)
	require.Len(t, matches, 1)
	archivePath := matches[0]
	binPath := "./dist/fake_linux_amd64_v1/fake_snapshot"
	require.FileExists(t, binPath)

	// reuse is observable via preserved mtimes
	oldTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(archivePath, oldTime, oldTime))
	require.NoError(t, os.Chtimes(binPath, oldTime, oldTime))
	createFile(t, "./dist/manual.txt", "manual")

	// second run: everything is complete, so binary and archive are reused
	cmd = newReleaseCmd()
	cmd.cmd.SetArgs(args)
	require.NoError(t, cmd.cmd.Execute())

	for _, p := range []string{archivePath, binPath} {
		st, err := os.Stat(p)
		require.NoError(t, err)
		require.Equal(t, oldTime.Unix(), st.ModTime().Unix(), "%s should be reused", p)
	}
	require.FileExists(t, "./dist/manual.txt")

	// simulate an interruption while (re)creating the archive: the file is
	// truncated and its manifest entry is gone
	require.NoError(t, os.Remove(archivePath))
	manifest := "./dist/artifacts.json"
	bts, err := os.ReadFile(manifest)
	require.NoError(t, err)
	var arts []*artifact.Artifact
	require.NoError(t, json.Unmarshal(bts, &arts))
	kept := arts[:0]
	for _, a := range arts {
		if filepath.Base(a.Path) == filepath.Base(archivePath) {
			continue
		}
		kept = append(kept, a)
	}
	out, err := json.Marshal(kept)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifest, out, 0o644))

	// third run: rebuilds only the archive, reuses the binary
	cmd = newReleaseCmd()
	cmd.cmd.SetArgs(args)
	require.NoError(t, cmd.cmd.Execute())
	require.FileExists(t, archivePath)
	st, err := os.Stat(archivePath)
	require.NoError(t, err)
	require.NotEqual(t, oldTime.Unix(), st.ModTime().Unix(), "archive should have been rebuilt")
	st, err = os.Stat(binPath)
	require.NoError(t, err)
	require.Equal(t, oldTime.Unix(), st.ModTime().Unix(), "binary should still be reused")
	require.FileExists(t, "./dist/manual.txt")

	// fourth run converges: the rebuilt archive is now reused as-is
	st, err = os.Stat(archivePath)
	require.NoError(t, err)
	rebuiltTime := st.ModTime().Unix()
	cmd = newReleaseCmd()
	cmd.cmd.SetArgs(args)
	require.NoError(t, cmd.cmd.Execute())
	st, err = os.Stat(archivePath)
	require.NoError(t, err)
	require.Equal(t, rebuiltTime, st.ModTime().Unix())
}
