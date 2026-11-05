// Package checksums provides a Pipe that creates .checksums files for
// each artifact.
package checksums

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/caarlos0/log"
	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/extrafiles"
	"github.com/goreleaser/goreleaser/v2/internal/gio"
	"github.com/goreleaser/goreleaser/v2/internal/semerrgroup"
	"github.com/goreleaser/goreleaser/v2/internal/tmpl"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
)

var (
	errNoArtifacts = errors.New("there are no artifacts to checksum")
	lock           sync.Mutex
)

// Markers delimiting the checksum lines managed by GoReleaser when
// Checksum.Preserve is enabled. Every other line in the file, such as
// comments and manually added checksums, is left untouched.
const (
	managedRegionBegin = "# goreleaser:checksums:begin"
	managedRegionEnd   = "# goreleaser:checksums:end"
)

// Pipe for checksums.
type Pipe struct{}

func (Pipe) String() string                 { return "calculating checksums" }
func (Pipe) Skip(ctx *context.Context) bool { return ctx.Config.Checksum.Disable }

// Default sets the pipe defaults.
func (Pipe) Default(ctx *context.Context) error {
	cs := &ctx.Config.Checksum
	if cs.Algorithm == "" {
		cs.Algorithm = "sha256"
	}
	if cs.NameTemplate == "" {
		if cs.Split {
			cs.NameTemplate = "{{ .ArtifactName }}.{{ .Algorithm }}"
		} else {
			cs.NameTemplate = "{{ .ProjectName }}_{{ .Version }}_checksums.txt"
		}
	}
	return nil
}

// Run the pipe.
func (Pipe) Run(ctx *context.Context) error {
	if ctx.Config.Checksum.Split {
		return splitChecksum(ctx)
	}

	return singleChecksum(ctx)
}

func splitChecksum(ctx *context.Context) error {
	artifactList, err := buildArtifactList(ctx)
	if err != nil {
		return err
	}

	for _, art := range artifactList {
		filename, err := tmpl.New(ctx).
			WithArtifact(art).
			WithExtraFields(tmpl.Fields{
				"Algorithm": ctx.Config.Checksum.Algorithm,
			}).
			Apply(ctx.Config.Checksum.NameTemplate)
		if err != nil {
			return fmt.Errorf("name template: %w", err)
		}
		filepath := filepath.Join(ctx.Config.Dist, filename)
		if err := refreshOne(ctx, *art, filepath); err != nil {
			return fmt.Errorf("%s: %w", art.Path, err)
		}
		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.Checksum,
			Path: filepath,
			Name: filename,
			Extra: map[string]any{
				artifact.ExtraChecksumOf: art.Path,
				artifact.ExtraRefresh: func() error {
					log.WithField("file", filename).Debug("refreshing checksums")
					return refreshOne(ctx, *art, filepath)
				},
			},
		})
	}
	return nil
}

func singleChecksum(ctx *context.Context) error {
	filename, err := tmpl.New(ctx).Apply(ctx.Config.Checksum.NameTemplate)
	if err != nil {
		return err
	}
	filepath := filepath.Join(ctx.Config.Dist, filename)
	if err := refreshAll(ctx, filepath); err != nil {
		if errors.Is(err, errNoArtifacts) {
			return nil
		}
		return err
	}
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.Checksum,
		Path: filepath,
		Name: filename,
		Extra: map[string]any{
			artifact.ExtraRefresh: func() error {
				log.WithField("file", filename).Debug("refreshing checksums")
				return refreshAll(ctx, filepath)
			},
		},
	})
	return nil
}

func refreshOne(ctx *context.Context, art artifact.Artifact, path string) error {
	check, err := art.Checksum(ctx.Config.Checksum.Algorithm)
	if err != nil {
		return err
	}
	return gio.WriteFile(path, []byte(check), 0o644)
}

func refreshAll(ctx *context.Context, filepath string) error {
	lock.Lock()
	defer lock.Unlock()

	artifactList, err := buildArtifactList(ctx)
	if err != nil {
		return err
	}

	g := semerrgroup.New(ctx.Parallelism)
	sumLines := make([]string, len(artifactList))
	for i, artifact := range artifactList {
		g.Go(func() error {
			sumLine, err := checksums(ctx.Config.Checksum.Algorithm, artifact)
			if err != nil {
				return err
			}
			sumLines[i] = sumLine
			return nil
		})
	}

	err = g.Wait()
	if err != nil {
		return err
	}

	// sort to ensure the signature is deterministic downstream
	slices.SortFunc(sumLines, func(a, b string) int {
		// sort by the filename of a checksum line ("{checksum}  {filename}\n")
		_, nameA, okA := strings.Cut(a, "  ")
		_, nameB, okB := strings.Cut(b, "  ")
		if !okA {
			nameA = a
		}
		if !okB {
			nameB = b
		}
		return cmp.Compare(nameA, nameB)
	})

	content := strings.Join(sumLines, "")
	if ctx.Config.Checksum.Preserve {
		content, err = reconcileManagedRegion(filepath, content)
		if err != nil {
			return err
		}
	}
	return gio.WriteFile(filepath, []byte(content), 0o644)
}

// reconcileManagedRegion regenerates the managed checksum region of the
// file at path, leaving every other line (comments and manually added
// checksums) byte-for-byte untouched.
//
// generated is the content of the managed region: checksum lines sorted
// and terminated by newlines. Lines for artifacts that no longer exist
// disappear because the region is fully derived from generated.
func reconcileManagedRegion(path string, generated string) (string, error) {
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	lines := strings.SplitAfter(string(current), "\n")
	// SplitAfter appends an empty final element when the content ends
	// with '\n'; drop it so marker lookup stays straightforward.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	begin := -1
	end := -1
	for i, line := range lines {
		switch strings.TrimSuffix(line, "\n") {
		case managedRegionBegin:
			if begin != -1 {
				return "", fmt.Errorf("checksums file %s contains multiple %q markers", path, managedRegionBegin)
			}
			begin = i
		case managedRegionEnd:
			if end != -1 {
				return "", fmt.Errorf("checksums file %s contains multiple %q markers", path, managedRegionEnd)
			}
			end = i
		}
	}

	block := strings.Join([]string{
		managedRegionBegin + "\n",
		generated,
		managedRegionEnd + "\n",
	}, "")

	switch {
	case begin == -1 && end == -1:
		// Plain, unmarked file written before preserve was enabled.
		// Adopt the checksum lines of current artifacts as the managed
		// region and keep everything else as custom content.
		return adoptUnmarkedFile(lines, block, generated), nil
	case begin == -1:
		return "", fmt.Errorf("checksums file %s contains %q without %q", path, managedRegionEnd, managedRegionBegin)
	case end == -1:
		return "", fmt.Errorf("checksums file %s contains %q without %q", path, managedRegionBegin, managedRegionEnd)
	case end < begin:
		return "", fmt.Errorf("checksums file %s has %q before %q", path, managedRegionEnd, managedRegionBegin)
	}

	prefix := strings.Join(lines[:begin], "")
	suffix := strings.Join(lines[end+1:], "")
	return prefix + block + suffix, nil
}

// adoptUnmarkedFile wraps generated in the managed region markers and
// preserves all lines that are not checksum lines of current artifacts,
// in their original order.
func adoptUnmarkedFile(lines []string, block, generated string) string {
	managedNames := make(map[string]struct{})
	for _, line := range strings.SplitAfter(generated, "\n") {
		if _, name, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "  "); ok && name != "" {
			managedNames[name] = struct{}{}
		}
	}

	var custom strings.Builder
	for _, line := range lines {
		if _, name, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "  "); ok {
			if _, managed := managedNames[name]; managed {
				// replaced by the freshly generated region
				continue
			}
		}
		custom.WriteString(line)
	}
	return block + custom.String()
}

func buildArtifactList(ctx *context.Context) ([]*artifact.Artifact, error) {
	filter := artifact.And(
		artifact.ByTypes(artifact.ReleaseUploadableTypes()...),
		artifact.Not(artifact.ByTypes(artifact.Checksum, artifact.Signature, artifact.Certificate)),
		artifact.ByIDs(ctx.Config.Checksum.IDs...),
	)
	artifactList := ctx.Artifacts.Filter(filter).List()

	extraFiles, err := extrafiles.Find(ctx, ctx.Config.Checksum.ExtraFiles)
	if err != nil {
		return nil, err
	}

	for name, path := range extraFiles {
		artifactList = append(artifactList, &artifact.Artifact{
			Name: name,
			Path: path,
			Type: artifact.UploadableFile,
		})
	}

	if len(artifactList) == 0 {
		return nil, errNoArtifacts
	}
	return artifactList, nil
}

func checksums(algorithm string, a *artifact.Artifact) (string, error) {
	log.WithField("file", a.Name).Debug("checksumming")
	sha, err := a.Checksum(algorithm)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v  %v\n", sha, a.Name), nil
}
