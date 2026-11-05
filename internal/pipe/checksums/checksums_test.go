package checksums

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/internal/testlib"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestDescription(t *testing.T) {
	require.NotEmpty(t, Pipe{}.String())
}

func TestPipe(t *testing.T) {
	const binary = "binary"
	const archive = binary + ".tar.gz"
	const linuxPackage = binary + ".rpm"
	const checksums = binary + "_bar_checksums.txt"
	const sum = "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc  "

	tests := map[string]struct {
		ids  []string
		want string
	}{
		"default": {
			want: strings.Join([]string{
				sum + binary,
				sum + linuxPackage,
				sum + archive,
			}, "\n") + "\n",
		},
		"select ids": {
			ids: []string{
				"id-1",
				"id-2",
			},
			want: strings.Join([]string{
				sum + binary,
				sum + archive,
			}, "\n") + "\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			folder := t.TempDir()
			file := filepath.Join(folder, binary)
			require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
			ctx := testctx.WrapWithCfg(t.Context(),
				config.Project{
					Dist:        folder,
					ProjectName: binary,
					Checksum: config.Checksum{
						NameTemplate: "{{ .ProjectName }}_{{ .Env.FOO }}_checksums.txt",
						Algorithm:    "sha256",
						IDs:          tt.ids,
					},
					Env: []string{"FOO=bar"},
				},
				testctx.WithCurrentTag("1.2.3"))

			ctx.Artifacts.Add(&artifact.Artifact{
				Name: binary,
				Path: file,
				Type: artifact.UploadableBinary,
				Extra: map[string]any{
					artifact.ExtraID: "id-1",
				},
			})
			ctx.Artifacts.Add(&artifact.Artifact{
				Name: archive,
				Path: file,
				Type: artifact.UploadableArchive,
				Extra: map[string]any{
					artifact.ExtraID: "id-2",
				},
			})
			ctx.Artifacts.Add(&artifact.Artifact{
				Name: linuxPackage,
				Path: file,
				Type: artifact.LinuxPackage,
				Extra: map[string]any{
					artifact.ExtraID: "id-3",
				},
			})
			require.NoError(t, Pipe{}.Run(ctx))
			var artifacts []string
			for _, a := range ctx.Artifacts.List() {
				artifacts = append(artifacts, a.Name)
				require.NoError(t, a.Refresh(), "refresh should not fail and yield same results as nothing changed")
			}
			require.Contains(t, artifacts, checksums, binary)
			bts, err := os.ReadFile(filepath.Join(folder, checksums))
			require.NoError(t, err)
			require.Contains(t, tt.want, string(bts))
		})
	}
}

func TestPipeSplit(t *testing.T) {
	const binary = "binary"
	const archive = binary + ".tar.gz"
	const linuxPackage = binary + ".rpm"
	const sum = "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc"

	folder := t.TempDir()
	file := filepath.Join(folder, binary)
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(),
		config.Project{
			Dist:        folder,
			ProjectName: "foo",
			Checksum: config.Checksum{
				Split: true,
			},
		})

	ctx.Artifacts.Add(&artifact.Artifact{
		Name: binary,
		Path: file,
		Type: artifact.UploadableBinary,
		Extra: map[string]any{
			artifact.ExtraID: "id-1",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: archive,
		Path: file,
		Type: artifact.UploadableArchive,
		Extra: map[string]any{
			artifact.ExtraID: "id-2",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: linuxPackage,
		Path: file,
		Type: artifact.LinuxPackage,
		Extra: map[string]any{
			artifact.ExtraID: "id-3",
		},
	})
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Run(ctx))

	require.NoError(t, ctx.Artifacts.Visit(func(a *artifact.Artifact) error {
		return a.Refresh()
	}))

	checks := ctx.Artifacts.Filter(artifact.ByType(artifact.Checksum)).List()
	require.Len(t, checks, 3)

	for _, check := range checks {
		require.NotEmpty(t, check.Extra[artifact.ExtraChecksumOf])
		bts, err := os.ReadFile(check.Path)
		require.NoError(t, err)
		require.Equal(t, sum, string(bts))
	}
}

func TestRefreshModifying(t *testing.T) {
	const binary = "binary"
	folder := t.TempDir()
	file := filepath.Join(folder, binary)
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        folder,
		ProjectName: binary,
		Checksum: config.Checksum{
			NameTemplate: "{{ .ProjectName }}_{{ .Env.FOO }}_checksums.txt",
			Algorithm:    "sha256",
		},
		Env: []string{"FOO=bar"},
	}, testctx.WithCurrentTag("1.2.3"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Name: binary,
		Path: file,
		Type: artifact.UploadableBinary,
	})
	require.NoError(t, Pipe{}.Run(ctx))
	checks := ctx.Artifacts.Filter(artifact.ByType(artifact.Checksum)).List()
	require.Len(t, checks, 1)
	previous, err := os.ReadFile(checks[0].Path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, []byte("some other string"), 0o644))
	require.NoError(t, checks[0].Refresh())
	current, err := os.ReadFile(checks[0].Path)
	require.NoError(t, err)
	require.NotEqual(t, string(previous), string(current))
}

func TestRefreshModifyingSplit(t *testing.T) {
	const binary = "binary"
	folder := t.TempDir()
	file := filepath.Join(folder, binary)
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        folder,
		ProjectName: binary,
		Checksum: config.Checksum{
			Split: true,
		},
		Env: []string{"FOO=bar"},
	}, testctx.WithCurrentTag("1.2.3"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Name: binary,
		Path: file,
		Type: artifact.UploadableBinary,
	})
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Run(ctx))
	checks := ctx.Artifacts.Filter(artifact.ByType(artifact.Checksum)).List()
	require.Len(t, checks, 1)
	previous, err := os.ReadFile(checks[0].Path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, []byte("some other string"), 0o644))
	require.NoError(t, checks[0].Refresh())
	current, err := os.ReadFile(checks[0].Path)
	require.NoError(t, err)
	require.NotEqual(t, string(previous), string(current))
}

func TestPipeFileNotExist(t *testing.T) {
	folder := t.TempDir()
	ctx := testctx.WrapWithCfg(t.Context(),
		config.Project{
			Dist: folder,
			Checksum: config.Checksum{
				NameTemplate: "checksums.txt",
			},
		},
		testctx.WithCurrentTag("1.2.3"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "nope",
		Path: "/nope",
		Type: artifact.UploadableBinary,
	})
	require.ErrorIs(t, Pipe{}.Run(ctx), os.ErrNotExist)
}

func TestPipeInvalidNameTemplate(t *testing.T) {
	binFile, err := os.CreateTemp(t.TempDir(), "goreleasertest-bin")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, binFile.Close()) })
	_, err = binFile.WriteString("fake artifact")
	require.NoError(t, err)

	for _, template := range []string{
		"{{ .Pro }_checksums.txt",
		"{{.Env.NOPE}}",
	} {
		for _, split := range []bool{true, false} {
			t.Run(fmt.Sprintf("split_%v_%s", split, template), func(t *testing.T) {
				folder := t.TempDir()
				ctx := testctx.WrapWithCfg(t.Context(),
					config.Project{
						Dist:        folder,
						ProjectName: "name",
						Checksum: config.Checksum{
							NameTemplate: template,
							Algorithm:    "sha256",
							Split:        split,
						},
					},
					testctx.WithCurrentTag("1.2.3"))

				ctx.Artifacts.Add(&artifact.Artifact{
					Name: "whatever",
					Type: artifact.UploadableBinary,
					Path: binFile.Name(),
				})
				testlib.RequireTemplateError(t, Pipe{}.Run(ctx))
			})
		}
	}
}

func TestPipeWhenNoArtifacts(t *testing.T) {
	ctx := testctx.Wrap(t.Context())
	require.NoError(t, Pipe{}.Run(ctx))
	require.Empty(t, ctx.Artifacts.List())
}

func TestDefault(t *testing.T) {
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Checksum: config.Checksum{},
	})

	require.NoError(t, Pipe{}.Default(ctx))
	require.Equal(
		t,
		"{{ .ProjectName }}_{{ .Version }}_checksums.txt",
		ctx.Config.Checksum.NameTemplate,
	)
	require.Equal(t, "sha256", ctx.Config.Checksum.Algorithm)
}

func TestDefaultSPlit(t *testing.T) {
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Checksum: config.Checksum{
			Split: true,
		},
	})

	require.NoError(t, Pipe{}.Default(ctx))
	require.Equal(
		t,
		"{{ .ArtifactName }}.{{ .Algorithm }}",
		ctx.Config.Checksum.NameTemplate,
	)
	require.Equal(t, "sha256", ctx.Config.Checksum.Algorithm)
}

func TestDefaultSet(t *testing.T) {
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Checksum: config.Checksum{
			NameTemplate: "checksums.txt",
		},
	})

	require.NoError(t, Pipe{}.Default(ctx))
	require.Equal(t, "checksums.txt", ctx.Config.Checksum.NameTemplate)
}

func TestPipeChecksumsSortByFilename(t *testing.T) {
	const binary = "binary"
	const checksums = "checksums.txt"
	const filePaths = "./testdata/order/*.txt"

	folder := t.TempDir()
	file := filepath.Join(folder, binary)
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))

	ctx := testctx.WrapWithCfg(t.Context(),
		config.Project{
			Dist:        folder,
			ProjectName: binary,
			Checksum: config.Checksum{
				Algorithm:    "sha256",
				NameTemplate: "checksums.txt",
				ExtraFiles: []config.ExtraFile{
					{Glob: filePaths},
				},
			},
		})

	ctx.Artifacts.Add(&artifact.Artifact{
		Name: binary,
		Path: file,
		Type: artifact.UploadableBinary,
	})

	require.NoError(t, Pipe{}.Run(ctx))

	bts, err := os.ReadFile(filepath.Join(folder, checksums))
	require.NoError(t, err)

	lines := strings.Split(string(bts), "\n")

	wantLinesOrder := []string{
		"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  a.txt",
		"3b64db95cb55c763391c707108489ae18b4112d783300de38e033b4c98c3deaf  b.txt",
		"61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc  binary",
		"64daa44ad493ff28a96effab6e77f1732a3d97d83241581b37dbd70a7a4900fe  c.txt",
		"5bf8aa57fc5a6bc547decf1cc6db63f10deb55a3c6c5df497d631fb3d95e1abf  d.txt",
	}

	for i, want := range wantLinesOrder {
		require.Equal(t, want, lines[i])
	}
}

func TestPipeCheckSumsWithExtraFiles(t *testing.T) {
	const binary = "binary"
	const checksums = "checksums.txt"
	const extraFileFooRelPath = "./testdata/foo.txt"
	const extraFileBarRelPath = "./testdata/**/bar.txt"
	const extraFileFoo = "foo.txt"
	const extraFileBar = "bar.txt"

	tests := map[string]struct {
		extraFiles []config.ExtraFile
		ids        []string
		want       []string
	}{
		"default": {
			extraFiles: nil,
			want: []string{
				binary,
			},
		},
		"one extra file": {
			extraFiles: []config.ExtraFile{
				{Glob: extraFileFooRelPath},
			},
			want: []string{
				extraFileFoo,
			},
		},
		"multiple extra files": {
			extraFiles: []config.ExtraFile{
				{Glob: extraFileFooRelPath},
				{Glob: extraFileBarRelPath},
			},
			want: []string{
				extraFileFoo,
				extraFileBar,
			},
		},
		"one extra file with no builds": {
			extraFiles: []config.ExtraFile{
				{Glob: extraFileFooRelPath},
			},
			ids: []string{"yada yada yada"},
			want: []string{
				extraFileFoo,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			folder := t.TempDir()
			file := filepath.Join(folder, binary)
			require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
			ctx := testctx.WrapWithCfg(t.Context(),
				config.Project{
					Dist:        folder,
					ProjectName: binary,
					Checksum: config.Checksum{
						Algorithm:    "sha256",
						NameTemplate: "checksums.txt",
						ExtraFiles:   tt.extraFiles,
						IDs:          tt.ids,
					},
				})

			ctx.Artifacts.Add(&artifact.Artifact{
				Name: binary,
				Path: file,
				Type: artifact.UploadableBinary,
				Extra: map[string]any{
					artifact.ExtraID: "id-1",
				},
			})

			require.NoError(t, Pipe{}.Run(ctx))

			bts, err := os.ReadFile(filepath.Join(folder, checksums))

			require.NoError(t, err)
			for _, want := range tt.want {
				if tt.extraFiles == nil {
					require.Contains(t, string(bts), "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc  "+want)
				} else {
					require.Contains(t, string(bts), "3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  "+want)
				}
			}

			_ = ctx.Artifacts.Visit(func(a *artifact.Artifact) error {
				if a.Path != file {
					return nil
				}
				if len(tt.ids) > 0 {
					return nil
				}
				checkSum := artifact.MustExtra[string](*a, artifact.ExtraChecksum)
				require.NotEmptyf(t, checkSum, "failed: %v", a.Path)
				return nil
			})
		})
	}
}

func TestExtraFilesNoMatch(t *testing.T) {
	dir := t.TempDir()
	ctx := testctx.WrapWithCfg(t.Context(),
		config.Project{
			Dist:        dir,
			ProjectName: "fake",
			Checksum: config.Checksum{
				Algorithm:    "sha256",
				NameTemplate: "checksums.txt",
				ExtraFiles:   []config.ExtraFile{{Glob: "./nope/nope.txt"}},
			},
		})

	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "fake",
		Path: "fake-path",
		Type: artifact.UploadableBinary,
	})

	require.NoError(t, Pipe{}.Default(ctx))
	require.EqualError(t, Pipe{}.Run(ctx), `globbing failed for pattern ./nope/nope.txt: matching "./nope/nope.txt": file does not exist`)
}

func TestSkip(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			Checksum: config.Checksum{
				Disable: true,
			},
		})

		require.True(t, Pipe{}.Skip(ctx))
	})

	t.Run("dont skip", func(t *testing.T) {
		require.False(t, Pipe{}.Skip(testctx.Wrap(t.Context())))
	})
}

func newPreserveProject(folder string) config.Project {
	return config.Project{
		Dist:        folder,
		ProjectName: "proj",
		Checksum: config.Checksum{
			NameTemplate: "checksums.txt",
			Algorithm:    "sha256",
			Preserve:     true,
		},
	}
}

// splitManagedRegion splits a checksums file content into the bytes
// before the managed region, the region body and the bytes after it.
func splitManagedRegion(t *testing.T, content string) (string, string, string) {
	t.Helper()
	beginLine := managedRegionBegin + "\n"
	endLine := managedRegionEnd + "\n"

	begin := strings.Index(content, beginLine)
	require.NotEqual(t, -1, begin, "missing begin marker in:\n%s", content)
	bodyStart := begin + len(beginLine)

	endRel := strings.Index(content[bodyStart:], endLine)
	require.NotEqual(t, -1, endRel, "missing end marker in:\n%s", content)
	bodyEnd := bodyStart + endRel

	return content[:begin], content[bodyStart:bodyEnd], content[bodyEnd+len(endLine):]
}

func TestPipeWithoutPreserveHasNoMarkers(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "binary")
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        folder,
		ProjectName: "proj",
		Checksum: config.Checksum{
			NameTemplate: "checksums.txt",
			Algorithm:    "sha256",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "binary",
		Path: file,
		Type: artifact.UploadableBinary,
	})

	require.NoError(t, Pipe{}.Run(ctx))

	bts, err := os.ReadFile(filepath.Join(folder, "checksums.txt"))
	require.NoError(t, err)
	require.NotContains(t, string(bts), managedRegionBegin)
	require.NotContains(t, string(bts), managedRegionEnd)
	require.Equal(t, "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc  binary\n", string(bts))
}

func TestPipePreserveCreatesManagedRegion(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "binary")
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "binary",
		Path: file,
		Type: artifact.UploadableBinary,
	})

	require.NoError(t, Pipe{}.Run(ctx))

	bts, err := os.ReadFile(filepath.Join(folder, "checksums.txt"))
	require.NoError(t, err)
	require.Equal(t, strings.Join([]string{
		managedRegionBegin,
		"61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc  binary",
		managedRegionEnd,
		"",
	}, "\n"), string(bts))
}

func TestPipePreserveIsIdempotent(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "binary")
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "binary",
		Path: file,
		Type: artifact.UploadableBinary,
	})

	require.NoError(t, Pipe{}.Run(ctx))
	path := filepath.Join(folder, "checksums.txt")

	first, err := os.ReadFile(path)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	checks := ctx.Artifacts.Filter(artifact.ByType(artifact.Checksum)).List()
	require.Len(t, checks, 1)
	require.NoError(t, checks[0].Refresh())

	second, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, bytes.Equal(first, second), "rerun changed the file:\n%s\n%s", first, second)

	info2, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info2.ModTime().Equal(info.ModTime()), "rerun rewrote an unchanged file")
}

func TestPipePreserveKeepsManualContent(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "binary")
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
	ctx.Artifacts.Add(&artifact.Artifact{
		Name: "binary",
		Path: file,
		Type: artifact.UploadableBinary,
	})

	require.NoError(t, Pipe{}.Run(ctx))
	path := filepath.Join(folder, "checksums.txt")
	first, err := os.ReadFile(path)
	require.NoError(t, err)

	// Simulate a user adding a header, an approval record and a checksum
	// line for an external artifact.
	prefix := "# build: 2026-11-05\n"
	suffix := "\n# release approved by alice\n# approval id: 42\ndeadbeef  external-blob.tar.gz\n"
	edited := make([]byte, 0, len(prefix)+len(first)+len(suffix))
	edited = append(edited, prefix...)
	edited = append(edited, first...)
	edited = append(edited, suffix...)
	require.NoError(t, os.WriteFile(path, edited, 0o644))

	// The artifact changes: its checksum must be refreshed inside the
	// region, while manual content stays byte-for-byte the same.
	require.NoError(t, os.WriteFile(file, []byte("some other string"), 0o644))
	checks := ctx.Artifacts.Filter(artifact.ByType(artifact.Checksum)).List()
	require.Len(t, checks, 1)
	require.NoError(t, checks[0].Refresh())

	bts, err := os.ReadFile(path)
	require.NoError(t, err)
	gotPrefix, gotBody, gotSuffix := splitManagedRegion(t, string(bts))
	require.Equal(t, prefix, gotPrefix)
	require.Equal(t, suffix, gotSuffix)

	bodyLines := strings.Split(strings.Trim(gotBody, "\n"), "\n")
	require.Equal(t, []string{"binary"}, func() []string {
		names := make([]string, 0, len(bodyLines))
		for _, line := range bodyLines {
			_, name, ok := strings.Cut(line, "  ")
			require.True(t, ok)
			names = append(names, name)
		}
		return names
	}())
	require.NotContains(t, gotBody, "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc")
	require.Contains(t, gotBody, "  binary")
	require.Contains(t, gotSuffix, "# release approved by alice")
	require.Contains(t, gotSuffix, "deadbeef  external-blob.tar.gz")

	// Another refresh must be a no-op.
	refreshed := string(bts)
	require.NoError(t, checks[0].Refresh())
	bts2, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, refreshed, string(bts2))
}

func TestPipePreserveReconcilesArtifactSet(t *testing.T) {
	folder := t.TempDir()

	binary := filepath.Join(folder, "binary")
	archive := filepath.Join(folder, "archive.tar.gz")
	extra := filepath.Join(folder, "extra.bin")
	require.NoError(t, os.WriteFile(binary, []byte("some string"), 0o644))
	require.NoError(t, os.WriteFile(archive, []byte("some string"), 0o644))

	ctx := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
	ctx.Artifacts.Add(&artifact.Artifact{Name: "binary", Path: binary, Type: artifact.UploadableBinary})
	ctx.Artifacts.Add(&artifact.Artifact{Name: "archive.tar.gz", Path: archive, Type: artifact.UploadableArchive})
	require.NoError(t, Pipe{}.Run(ctx))

	// User appends an external checksum after the first run.
	path := filepath.Join(folder, "checksums.txt")
	suffix := "# external\ndeadbeef  external-blob.tar.gz\n"
	require.NoError(t, os.WriteFile(path, append(mustReadFile(t, path), []byte(suffix)...), 0o644))

	// Second run: archive disappears, extra appears.
	require.NoError(t, os.WriteFile(extra, []byte("extra content"), 0o644))
	ctx2 := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
	ctx2.Artifacts.Add(&artifact.Artifact{Name: "binary", Path: binary, Type: artifact.UploadableBinary})
	ctx2.Artifacts.Add(&artifact.Artifact{Name: "extra.bin", Path: extra, Type: artifact.UploadableBinary})
	require.NoError(t, Pipe{}.Run(ctx2))

	bts := mustReadFile(t, path)
	_, body, gotSuffix := splitManagedRegion(t, string(bts))
	require.Equal(t, suffix, gotSuffix)
	require.Contains(t, body, "  binary")
	require.Contains(t, body, "  extra.bin")
	require.NotContains(t, body, "archive.tar.gz", "lines for disappeared artifacts must be removed")
	// region is sorted by filename
	require.Less(t, strings.Index(body, "  binary"), strings.Index(body, "  extra.bin"))
	require.Contains(t, gotSuffix, "deadbeef  external-blob.tar.gz")

	// Rerunning with the same input is stable.
	require.NoError(t, Pipe{}.Run(ctx2))
	bts2 := mustReadFile(t, path)
	require.True(t, bytes.Equal(bts, bts2))
}

func TestPipePreserveAdoptsPlainFile(t *testing.T) {
	const sum = "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc"

	t.Run("plain file with manual lines", func(t *testing.T) {
		folder := t.TempDir()
		file := filepath.Join(folder, "binary")
		require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))

		// Old-style file, written before preserve was enabled: tool
		// lines mixed with comments and external/stale checksum lines.
		path := filepath.Join(folder, "checksums.txt")
		require.NoError(t, os.WriteFile(path, []byte(strings.Join([]string{
			sum + "  binary",
			"# manually tracked external product",
			"0000000000000000000000000000000000000000000000000000000000000000  external-blob.tar.gz",
			"1111111111111111111111111111111111111111111111111111111111111111  removed-binary",
			"",
		}, "\n")), 0o644))

		ctx := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
		ctx.Artifacts.Add(&artifact.Artifact{Name: "binary", Path: file, Type: artifact.UploadableBinary})
		require.NoError(t, Pipe{}.Run(ctx))

		bts := mustReadFile(t, path)
		prefix, body, suffix := splitManagedRegion(t, string(bts))
		require.Empty(t, prefix)
		require.Equal(t, sum+"  binary\n", body)
		require.Equal(t, strings.Join([]string{
			"# manually tracked external product",
			"0000000000000000000000000000000000000000000000000000000000000000  external-blob.tar.gz",
			"1111111111111111111111111111111111111111111111111111111111111111  removed-binary",
			"",
		}, "\n"), suffix)
	})

	t.Run("plain file with tool lines only", func(t *testing.T) {
		folder := t.TempDir()
		file := filepath.Join(folder, "binary")
		require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))

		path := filepath.Join(folder, "checksums.txt")
		require.NoError(t, os.WriteFile(path, []byte(sum+"  binary\n"), 0o644))

		ctx := testctx.WrapWithCfg(t.Context(), newPreserveProject(folder))
		ctx.Artifacts.Add(&artifact.Artifact{Name: "binary", Path: file, Type: artifact.UploadableBinary})
		require.NoError(t, Pipe{}.Run(ctx))

		require.Equal(t, strings.Join([]string{
			managedRegionBegin,
			sum + "  binary",
			managedRegionEnd,
			"",
		}, "\n"), string(mustReadFile(t, path)))
	})
}

func TestReconcileManagedRegionMalformed(t *testing.T) {
	generated := "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc  binary\n"

	for name, content := range map[string]string{
		"begin without end": strings.Join([]string{
			managedRegionBegin,
			generated,
			"# manual",
		}, "\n"),
		"end without begin": strings.Join([]string{
			generated,
			managedRegionEnd,
		}, "\n"),
		"multiple begin": strings.Join([]string{
			managedRegionBegin,
			generated,
			managedRegionEnd,
			managedRegionBegin,
		}, "\n"),
		"end before begin": strings.Join([]string{
			managedRegionEnd,
			managedRegionBegin,
			generated,
			managedRegionEnd,
		}, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			folder := t.TempDir()
			path := filepath.Join(folder, "checksums.txt")
			require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

			_, err := reconcileManagedRegion(path, generated)
			require.Error(t, err)

			// A failed reconcile must not touch the file.
			bts, rerr := os.ReadFile(path)
			require.NoError(t, rerr)
			require.Equal(t, content, string(bts))
		})
	}
}

func TestReconcileManagedRegionMissingFile(t *testing.T) {
	generated := "abc  binary\n"
	got, err := reconcileManagedRegion(filepath.Join(t.TempDir(), "checksums.txt"), generated)
	require.NoError(t, err)
	require.Equal(t, managedRegionBegin+"\n"+generated+managedRegionEnd+"\n", got)
}

func TestPipePreserveSplitIsIgnored(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "binary")
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist: folder,
		Checksum: config.Checksum{
			Split:    true,
			Preserve: true,
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{Name: "binary", Path: file, Type: artifact.UploadableBinary})
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Run(ctx))

	checks := ctx.Artifacts.Filter(artifact.ByType(artifact.Checksum)).List()
	require.Len(t, checks, 1)
	bts, err := os.ReadFile(checks[0].Path)
	require.NoError(t, err)
	require.Equal(t, "61d034473102d7dac305902770471fd50f4c5b26f6831a56dd90b5184b3c30fc", string(bts))
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	bts, err := os.ReadFile(path)
	require.NoError(t, err)
	return bts
}

func TestChecksumExcludesSignaturesAndCertificates(t *testing.T) {
	folder := t.TempDir()
	file := filepath.Join(folder, "binary")
	require.NoError(t, os.WriteFile(file, []byte("some string"), 0o644))

	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        folder,
		ProjectName: "proj",
		Checksum: config.Checksum{
			NameTemplate: "checksums.txt",
			Algorithm:    "sha256",
		},
	}, testctx.WithCurrentTag("1.0.0"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Name:  "binary",
		Path:  file,
		Type:  artifact.UploadableBinary,
		Extra: map[string]any{artifact.ExtraID: "default"},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Name:  "binary.sig",
		Path:  file,
		Type:  artifact.Signature,
		Extra: map[string]any{artifact.ExtraID: "default"},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Name:  "binary.pem",
		Path:  file,
		Type:  artifact.Certificate,
		Extra: map[string]any{artifact.ExtraID: "default"},
	})

	require.NoError(t, Pipe{}.Run(ctx))

	bts, err := os.ReadFile(filepath.Join(folder, "checksums.txt"))
	require.NoError(t, err)

	content := string(bts)
	require.Contains(t, content, "binary")
	require.NotContains(t, content, "binary.sig", "signatures must not be checksummed")
	require.NotContains(t, content, "binary.pem", "certificates must not be checksummed")
}
