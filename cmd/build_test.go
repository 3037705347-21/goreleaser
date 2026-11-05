package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/pipeline"
	"github.com/goreleaser/goreleaser/v2/internal/skips"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
	"github.com/stretchr/testify/require"
)

func TestBuildAutoSnapshot(t *testing.T) {
	// --auto-snapshot on a clean tree does not imply --snapshot, so this also
	// covers a build that runs the validation pipe.
	t.Run("clean", func(t *testing.T) {
		setup(t)
		cmd := newBuildCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_*/fake")
		require.NoError(t, err)
		require.Len(t, matches, 1)
	})

	t.Run("dirty", func(t *testing.T) {
		setup(t)
		createFile(t, "foo", "force dirty tree")
		cmd := newBuildCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_*/fake_snapshot")
		require.NoError(t, err)
		require.Len(t, matches, 1)
	})
}

func TestBuildAutoSnapshotWithProConfig(t *testing.T) {
	t.Run("explicit snapshot", func(t *testing.T) {
		setupPro(t)
		cmd := newBuildCmd()
		cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_*/fake_snapshot")
		require.NoError(t, err)
		require.Len(t, matches, 1)
	})

	t.Run("dirty automatic snapshot", func(t *testing.T) {
		setupPro(t)
		createFile(t, "foo", "force dirty tree")
		cmd := newBuildCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.NoError(t, cmd.cmd.Execute())
		matches, err := filepath.Glob("./dist/fake_*/fake_snapshot")
		require.NoError(t, err)
		require.Len(t, matches, 1)
	})

	t.Run("clean automatic snapshot", func(t *testing.T) {
		setupPro(t)
		cmd := newBuildCmd()
		cmd.cmd.SetArgs([]string{"--auto-snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
		require.ErrorIs(t, cmd.cmd.Execute(), config.ErrProConfig)
	})
}

func TestBuildSingleTarget(t *testing.T) {
	setup(t)
	cmd := newBuildCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=1m", "--parallelism=2", "--deprecated", "--single-target"})
	require.NoError(t, cmd.cmd.Execute())
}

func TestBuildInvalidConfig(t *testing.T) {
	mktmp(t)
	createFile(t, "goreleaser.yml", "version: 2\nfoo: bar")
	cmd := newBuildCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=1m", "--parallelism=2", "--deprecated"})
	require.EqualError(t, cmd.cmd.Execute(), "yaml: unmarshal errors:\n  line 2: field foo not found in type config.Project")
}

func TestBuildBrokenProject(t *testing.T) {
	setup(t)
	createFile(t, "main.go", "not a valid go file")
	cmd := newBuildCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=1m", "--parallelism=2"})
	require.ErrorContains(t, cmd.cmd.Execute(), "failed to parse dir: .: main.go:1:1: expected 'package', found not")
}

func TestSetupPipeline(t *testing.T) {
	t.Run("regular", func(t *testing.T) {
		require.Equal(
			t,
			slices.Clone(pipeline.BuildCmdPipeline),
			setupPipeline(testctx.Wrap(t.Context()), buildOpts{}),
		)
	})

	t.Run("single-target", func(t *testing.T) {
		require.Equal(
			t,
			slices.Clone(pipeline.BuildCmdPipeline),
			setupPipeline(testctx.Wrap(t.Context()), buildOpts{
				singleTarget: true,
			}),
		)
	})

	t.Run("single-target and id", func(t *testing.T) {
		require.Equal(
			t,
			slices.Clone(pipeline.BuildCmdPipeline),
			setupPipeline(testctx.Wrap(t.Context()), buildOpts{
				singleTarget: true,
				ids:          []string{"foo"},
			}),
		)
	})

	t.Run("single-target and id, given output", func(t *testing.T) {
		require.Equal(
			t,
			append(slices.Clone(pipeline.BuildCmdPipeline), withOutputPipe{"."}),
			setupPipeline(
				testctx.WrapWithCfg(t.Context(), config.Project{
					Builds: []config.Build{{}},
				}),
				buildOpts{
					singleTarget: true,
					ids:          []string{"foo"},
					output:       ".",
				},
			),
		)
	})

	t.Run("single-target and single build on config", func(t *testing.T) {
		require.Equal(
			t,
			slices.Clone(pipeline.BuildCmdPipeline),
			setupPipeline(
				testctx.WrapWithCfg(t.Context(), config.Project{
					Builds: []config.Build{{}},
				}),

				buildOpts{
					singleTarget: true,
				},
			),
		)
	})

	t.Run("single-target, id and output", func(t *testing.T) {
		require.Equal(
			t,
			append(slices.Clone(pipeline.BuildCmdPipeline), withOutputPipe{"foobar"}),
			setupPipeline(
				testctx.WrapWithCfg(t.Context(), config.Project{
					Builds: []config.Build{{}},
				}),
				buildOpts{
					singleTarget: true,
					ids:          []string{"foo"},
					output:       "foobar",
				},
			),
		)
	})

	t.Run("single-target, single build on config and output", func(t *testing.T) {
		require.Equal(
			t,
			append(slices.Clone(pipeline.BuildCmdPipeline), withOutputPipe{"zaz"}),
			setupPipeline(
				testctx.WrapWithCfg(t.Context(), config.Project{
					Builds: []config.Build{{}},
				}),

				buildOpts{
					singleTarget: true,
					output:       "zaz",
				},
			),
		)
	})
}

func TestWithOutputPipe(t *testing.T) {
	t.Run("single binary", func(t *testing.T) {
		mktmp(t)
		createFile(t, "a", "A")
		ctx := testctx.Wrap(t.Context())
		ctx.Artifacts.Add(&artifact.Artifact{
			Name: "a",
			Path: "a",
			Type: artifact.Binary,
		})

		require.NoError(t, (withOutputPipe{"picked"}).Run(ctx))
		bts, err := os.ReadFile("picked")
		require.NoError(t, err)
		require.Equal(t, "A", string(bts))
	})

	for name, binaries := range map[string][]string{
		"a first": {"a", "b"},
		"b first": {"b", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			mktmp(t)
			createFile(t, "a", "A")
			createFile(t, "b", "B")
			ctx := testctx.Wrap(t.Context())
			for _, binary := range binaries {
				ctx.Artifacts.Add(&artifact.Artifact{
					Name: binary,
					Path: binary,
					Type: artifact.Binary,
				})
			}

			require.ErrorContains(t, (withOutputPipe{"picked"}).Run(ctx), "--output requires a single build")
			require.NoFileExists(t, "picked")
		})
	}
}

func TestBuildFlags(t *testing.T) {
	setup := func(opts buildOpts) *context.Context {
		ctx := testctx.Wrap(t.Context())
		require.NoError(t, setupBuildContext(ctx, opts))
		return ctx
	}

	t.Run("action", func(t *testing.T) {
		ctx := setup(buildOpts{})
		require.Equal(t, context.ActionBuild, ctx.Action)
	})

	t.Run("snapshot", func(t *testing.T) {
		ctx := setup(buildOpts{
			snapshot: true,
		})
		require.True(t, ctx.Snapshot)
		requireAll(t, ctx, skips.Validate)
		require.True(t, ctx.SkipTokenCheck)
	})

	t.Run("skips", func(t *testing.T) {
		ctx := setup(buildOpts{
			skips: []string{
				string(skips.Validate),
				string(skips.PostBuildHooks),
			},
		})
		requireAll(t, ctx, skips.Validate, skips.PostBuildHooks)
		require.True(t, ctx.SkipTokenCheck)
	})

	t.Run("parallelism", func(t *testing.T) {
		require.Equal(t, 1, setup(buildOpts{
			parallelism: 1,
		}).Parallelism)
	})

	t.Run("rm dist", func(t *testing.T) {
		require.True(t, setup(buildOpts{
			clean: true,
		}).Clean)
	})

	t.Run("id", func(t *testing.T) {
		t.Run("match", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Builds: []config.Build{
					{
						ID: "default",
					},
					{
						ID: "foo",
					},
				},
			})

			require.NoError(t, setupBuildContext(ctx, buildOpts{
				ids: []string{"foo"},
			}))
		})

		t.Run("match-multiple", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Builds: []config.Build{
					{
						ID: "default",
					},
					{
						ID: "foo",
					},
				},
			})

			require.NoError(t, setupBuildContext(ctx, buildOpts{
				ids: []string{"foo", "default"},
			}))
		})

		t.Run("match-multiple with output", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Builds: []config.Build{
					{
						ID: "default",
					},
					{
						ID: "foo",
					},
				},
			})

			require.ErrorContains(t, setupBuildContext(ctx, buildOpts{
				singleTarget: true,
				ids:          []string{"foo", "default"},
				output:       "picked",
			}), "--output requires a single build")
		})

		t.Run("match-partial", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Builds: []config.Build{
					{
						ID: "default",
					},
					{
						ID: "foo",
					},
				},
			})

			require.NoError(t, setupBuildContext(ctx, buildOpts{
				ids: []string{"foo", "notdefault"},
			}))
		})

		t.Run("dont match", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Builds: []config.Build{
					{
						ID: "foo",
					},
					{
						ID: "bazz",
					},
				},
			})

			require.EqualError(t, setupBuildContext(ctx, buildOpts{
				ids: []string{"bar", "fooz"},
			}), "no builds with ids bar, fooz")
		})

		t.Run("default config", func(t *testing.T) {
			ctx := testctx.Wrap(t.Context())
			require.NoError(t, setupBuildContext(ctx, buildOpts{
				ids: []string{"aaa"},
			}))
		})

		t.Run("single build config", func(t *testing.T) {
			ctx := testctx.WrapWithCfg(t.Context(), config.Project{
				Builds: []config.Build{
					{
						ID: "foo",
					},
				},
			})

			require.NoError(t, setupBuildContext(ctx, buildOpts{
				ids: []string{"not foo but doesnt matter"},
			}))
		})
	})
}

func writeBuildYAML(t *testing.T, arches string) {
	t.Helper()
	createFile(t, "goreleaser.yml", "builds:\n"+
		"- id: fake\n"+
		"  binary: fake\n"+
		"  goos: [linux]\n"+
		"  goarch: ["+arches+"]\n")
}

func TestBuildResumeAfterInterruption(t *testing.T) {
	setup(t)

	// first, successful build for amd64, arm64 and 386
	writeBuildYAML(t, "amd64, arm64, '386'")
	cmd := newBuildCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=2m", "--parallelism=2", "--deprecated"})
	require.NoError(t, cmd.cmd.Execute())

	amd64Bin := "./dist/fake_linux_amd64_v1/fake"
	arm64Bin := "./dist/fake_linux_arm64_v8.0/fake"
	i386Bin := "./dist/fake_linux_386_sse2/fake"
	for _, p := range []string{amd64Bin, arm64Bin, i386Bin} {
		require.FileExists(t, p)
	}

	// the configuration no longer builds 386
	writeBuildYAML(t, "amd64, arm64")

	// simulate a checkpoint interrupted after amd64 and 386, before arm64:
	// the arm64 binary and its manifest entry are gone
	require.NoError(t, os.Remove(arm64Bin))
	manifest := "./dist/artifacts.json"
	bts, err := os.ReadFile(manifest)
	require.NoError(t, err)
	var arts []*artifact.Artifact
	require.NoError(t, json.Unmarshal(bts, &arts))
	kept := arts[:0]
	for _, a := range arts {
		if a.Target == "linux_arm64_v8.0" {
			continue
		}
		kept = append(kept, a)
	}
	out, err := json.Marshal(kept)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifest, out, 0o644))

	// a manually placed file must survive
	createFile(t, "./dist/manual.txt", "manual")

	// pin the amd64 mtime so reuse is detectable
	oldTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(amd64Bin, oldTime, oldTime))

	// second run: resumes the same version, rebuilds arm64, reuses amd64,
	// drops 386 and keeps the manual file
	cmd = newBuildCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=2m", "--parallelism=2", "--deprecated"})
	require.NoError(t, cmd.cmd.Execute())

	st, err := os.Stat(amd64Bin)
	require.NoError(t, err)
	require.Equal(t, oldTime.Unix(), st.ModTime().Unix(), "amd64 binary should have been reused, not rebuilt")

	require.FileExists(t, arm64Bin)
	require.NoFileExists(t, i386Bin)
	_, err = os.Stat("./dist/fake_linux_386_sse2")
	require.True(t, os.IsNotExist(err), "empty removed-target directory should be pruned")
	require.FileExists(t, "./dist/manual.txt")

	bts, err = os.ReadFile(manifest)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(bts, &arts))
	var targets []string
	for _, a := range arts {
		if a.Type == artifact.Binary {
			targets = append(targets, a.Target)
		}
	}
	require.ElementsMatch(t, []string{"linux_amd64_v1", "linux_arm64_v8.0"}, targets)

	// third run converges to the exact same result
	cmd = newBuildCmd()
	cmd.cmd.SetArgs([]string{"--snapshot", "--timeout=2m", "--parallelism=2", "--deprecated"})
	require.NoError(t, cmd.cmd.Execute())
	st, err = os.Stat(amd64Bin)
	require.NoError(t, err)
	require.Equal(t, oldTime.Unix(), st.ModTime().Unix())
	require.FileExists(t, arm64Bin)
	require.NoFileExists(t, i386Bin)
	require.FileExists(t, "./dist/manual.txt")
}
