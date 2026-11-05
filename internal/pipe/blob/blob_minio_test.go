package blob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	stdctx "context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/goreleaser/goreleaser/v2/internal/artifact"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/internal/testlib"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/goreleaser/goreleaser/v2/pkg/context"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"gocloud.dev/blob"
)

const (
	minioUser     = "minio"
	minioPwd      = "miniostorage"
	minioImage    = "cgr.dev/chainguard/minio@sha256:0f95aa412a12351a95bb43c3b54b66440eb0aa022bb3f3458942678a489e915b"
	minioRepo     = "goreleaser-test-minio"
	minioTag      = "pinned"
	containerName = "goreleaserTestMinio"
)

var listen string

func TestMain(m *testing.M) {
	if !testlib.InPath("docker") || testlib.IsWindows() || !testlib.IsDockerRunning(stdctx.Background()) {
		// there's no minio windows image
		m.Run()
		return
	}
	prepareEnv()

	requireNoErr := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}

	pool := testlib.MustDockerPool(log.Default())
	testlib.MustKillContainer(log.Default(), containerName)
	requireNoErr(pool.Client.PullImage(docker.PullImageOptions{
		Repository: minioImage,
		Context:    stdctx.Background(),
	}, docker.AuthConfiguration{}))
	requireNoErr(pool.Client.TagImage(minioImage, docker.TagImageOptions{
		Repo:    minioRepo,
		Tag:     minioTag,
		Force:   true,
		Context: stdctx.Background(),
	}))

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Name:       containerName,
		Repository: minioRepo,
		Tag:        minioTag,
		Env: []string{
			"MINIO_ROOT_USER=" + minioUser,
			"MINIO_ROOT_PASSWORD=" + minioPwd,
		},
		ExposedPorts: []string{"9000/tcp", "9001/tcp"},
		Cmd:          []string{"server", "/data", "--console-address", ":9001"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
	})
	requireNoErr(err)
	requireNoErr(pool.Retry(func() error {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/minio/health/ready", resource.GetPort("9000/tcp")))
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}))
	listen = "localhost:" + resource.GetPort("9000/tcp")

	m.Run()

	requireNoErr(pool.Purge(resource))
}

func TestMinioUpload(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	name := "basic"
	directory := t.TempDir()
	srcpath := filepath.Join(directory, "source.tar.gz")
	tgzpath := filepath.Join(directory, "bin.tar.gz")
	debpath := filepath.Join(directory, "bin.deb")
	checkpath := filepath.Join(directory, "check.txt")
	metapath := filepath.Join(directory, "metadata.json")
	sigpath := filepath.Join(directory, "f.sig")
	certpath := filepath.Join(directory, "f.pem")
	require.NoError(t, os.WriteFile(checkpath, []byte("fake checksums"), 0o744))
	require.NoError(t, os.WriteFile(metapath, []byte(`{"fake":true}`), 0o744))
	require.NoError(t, os.WriteFile(srcpath, []byte("fake\nsrc"), 0o744))
	require.NoError(t, os.WriteFile(tgzpath, []byte("fake\ntargz"), 0o744))
	require.NoError(t, os.WriteFile(debpath, []byte("fake\ndeb"), 0o744))
	require.NoError(t, os.WriteFile(sigpath, []byte("fake\nsig"), 0o744))
	require.NoError(t, os.WriteFile(certpath, []byte("fake\ncert"), 0o744))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        directory,
		ProjectName: "testupload",
		Blobs: []config.Blob{
			{
				Provider:           "s3",
				Bucket:             name,
				Region:             "us-east",
				Endpoint:           "http://" + listen,
				IDs:                []string{"foo", "bar"},
				CacheControl:       []string{"max-age=9999"},
				ContentDisposition: "inline",
				IncludeMeta:        true,
				ExtraFiles: []config.ExtraFile{
					{
						Glob: "./testdata/*.golden",
					},
				},
			},
		},
	}, testctx.WithCurrentTag("v1.0.0"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.Metadata,
		Name: "metadata.json",
		Path: metapath,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.Checksum,
		Name: "checksum.txt",
		Path: checkpath,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.Signature,
		Name: "checksum.txt.sig",
		Path: sigpath,
		Extra: map[string]any{
			artifact.ExtraID: "foo",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.Certificate,
		Name: "checksum.pem",
		Path: certpath,
		Extra: map[string]any{
			artifact.ExtraID: "foo",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableSourceArchive,
		Name: "source.tar.gz",
		Path: srcpath,
		Extra: map[string]any{
			artifact.ExtraFormat: "tar.gz",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "bin.tar.gz",
		Path: tgzpath,
		Extra: map[string]any{
			artifact.ExtraID: "foo",
		},
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.LinuxPackage,
		Name: "bin.deb",
		Path: debpath,
		Extra: map[string]any{
			artifact.ExtraID: "bar",
		},
	})

	setupBucket(t, name)
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Publish(ctx))

	require.ElementsMatch(t, getFiles(t, ctx, ctx.Config.Blobs[0]), []string{
		"testupload/v1.0.0/bin.deb",
		"testupload/v1.0.0/bin.tar.gz",
		"testupload/v1.0.0/metadata.json",
		"testupload/v1.0.0/checksum.txt",
		"testupload/v1.0.0/checksum.txt.sig",
		"testupload/v1.0.0/checksum.pem",
		"testupload/v1.0.0/source.tar.gz",
		"testupload/v1.0.0/file.golden",
	})
}

func TestMinioUploadCustomBucketID(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	name := "fromenv"
	directory := t.TempDir()
	tgzpath := filepath.Join(directory, "bin.tar.gz")
	debpath := filepath.Join(directory, "bin.deb")
	require.NoError(t, os.WriteFile(tgzpath, []byte("fake\ntargz"), 0o744))
	require.NoError(t, os.WriteFile(debpath, []byte("fake\ndeb"), 0o744))
	// Set custom BUCKET_ID env variable.
	t.Setenv("BUCKET_ID", name)
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        directory,
		ProjectName: "testupload",
		Blobs: []config.Blob{
			{
				Provider: "s3",
				Bucket:   "{{.Env.BUCKET_ID}}",
				Endpoint: "http://" + listen,
			},
		},
	}, testctx.WithCurrentTag("v1.0.0"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "bin.tar.gz",
		Path: tgzpath,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.LinuxPackage,
		Name: "bin.deb",
		Path: debpath,
	})

	setupBucket(t, name)
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Publish(ctx))
}

func TestMinioUploadExtraFilesOnly(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	name := "only-extra-files"
	directory := t.TempDir()
	tgzpath := filepath.Join(directory, "bin.tar.gz")
	debpath := filepath.Join(directory, "bin.deb")
	require.NoError(t, os.WriteFile(tgzpath, []byte("fake\ntargz"), 0o744))
	require.NoError(t, os.WriteFile(debpath, []byte("fake\ndeb"), 0o744))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        directory,
		ProjectName: "testupload",
		Blobs: []config.Blob{
			{
				Provider:       "s3",
				Bucket:         name,
				Endpoint:       "http://" + listen,
				IncludeMeta:    true,
				ExtraFilesOnly: true,
				ExtraFiles: []config.ExtraFile{
					{
						Glob: "./testdata/*.golden",
					},
				},
			},
		},
	}, testctx.WithCurrentTag("v1.0.0"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "bin.tar.gz",
		Path: tgzpath,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.LinuxPackage,
		Name: "bin.deb",
		Path: debpath,
	})

	setupBucket(t, name)
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Publish(ctx))

	require.ElementsMatch(t, getFiles(t, ctx, ctx.Config.Blobs[0]), []string{
		"testupload/v1.0.0/file.golden",
	})
}

func TestMinioUploadRootDirectory(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	name := "rootdir"
	directory := t.TempDir()
	tgzpath := filepath.Join(directory, "bin.tar.gz")
	debpath := filepath.Join(directory, "bin.deb")
	require.NoError(t, os.WriteFile(tgzpath, []byte("fake\ntargz"), 0o744))
	require.NoError(t, os.WriteFile(debpath, []byte("fake\ndeb"), 0o744))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        directory,
		ProjectName: "testupload",
		Blobs: []config.Blob{
			{
				Provider:  "s3",
				Bucket:    name,
				Directory: "/",
				Endpoint:  "http://" + listen,
			},
		},
	}, testctx.WithCurrentTag("v1.0.0"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "bin.tar.gz",
		Path: tgzpath,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.LinuxPackage,
		Name: "bin.deb",
		Path: debpath,
	})

	setupBucket(t, name)
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Publish(ctx))
}

func TestMinioUploadInvalidCustomBucketID(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	directory := t.TempDir()
	tgzpath := filepath.Join(directory, "bin.tar.gz")
	debpath := filepath.Join(directory, "bin.deb")
	require.NoError(t, os.WriteFile(tgzpath, []byte("fake\ntargz"), 0o744))
	require.NoError(t, os.WriteFile(debpath, []byte("fake\ndeb"), 0o744))
	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		Dist:        directory,
		ProjectName: "testupload",
		Blobs: []config.Blob{
			{
				Provider: "s3",
				Bucket:   "{{.Bad}}",
				Endpoint: "http://" + listen,
			},
		},
	}, testctx.WithCurrentTag("v1.1.0"))

	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "bin.tar.gz",
		Path: tgzpath,
	})
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.LinuxPackage,
		Name: "bin.deb",
		Path: debpath,
	})

	require.NoError(t, Pipe{}.Default(ctx))
	require.Error(t, Pipe{}.Publish(ctx))
}

func TestMinioUploadSkip(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	name := "skip"
	directory := t.TempDir()
	debpath := filepath.Join(directory, "bin.deb")
	tgzpath := filepath.Join(directory, "bin.tar.gz")
	require.NoError(t, os.WriteFile(tgzpath, []byte("fake\ntargz"), 0o744))
	require.NoError(t, os.WriteFile(debpath, []byte("fake\ndeb"), 0o744))

	buildCtx := func(uploadID string) *context.Context {
		ctx := testctx.WrapWithCfg(t.Context(),
			config.Project{
				Dist:        directory,
				ProjectName: "testupload",
				Blobs: []config.Blob{
					{
						Provider: "s3",
						Bucket:   name,
						Region:   "us-east",
						Endpoint: "http://" + listen,
						IDs:      []string{"foo"},
						Disable:  `{{ eq .Env.UPLOAD_ID "foo" }}`,
					},
					{
						Provider: "s3",
						Bucket:   name,
						Region:   "us-east",
						Endpoint: "http://" + listen,
						Disable:  `{{ eq .Env.UPLOAD_ID "bar" }}`,
						IDs:      []string{"bar"},
					},
				},
			},
			testctx.WithCurrentTag("v1.0.0"),
			testctx.WithEnv(map[string]string{
				"UPLOAD_ID": uploadID,
			}))

		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.UploadableArchive,
			Name: "bin.tar.gz",
			Path: tgzpath,
			Extra: map[string]any{
				artifact.ExtraID: "foo",
			},
		})
		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.LinuxPackage,
			Name: "bin.deb",
			Path: debpath,
			Extra: map[string]any{
				artifact.ExtraID: "bar",
			},
		})
		return ctx
	}

	setupBucket(t, name)

	t.Run("upload only foo", func(t *testing.T) {
		ctx := buildCtx("foo")
		require.NoError(t, Pipe{}.Default(ctx))
		testlib.AssertSkipped(t, Pipe{}.Publish(ctx))
		require.Subset(t, getFiles(t, ctx, ctx.Config.Blobs[0]), []string{
			"testupload/v1.0.0/bin.deb",
		})
	})

	t.Run("upload only bar", func(t *testing.T) {
		ctx := buildCtx("bar")
		require.NoError(t, Pipe{}.Default(ctx))
		testlib.AssertSkipped(t, Pipe{}.Publish(ctx))
		require.Subset(t, getFiles(t, ctx, ctx.Config.Blobs[0]), []string{
			"testupload/v1.0.0/bin.tar.gz",
		})
	})

	t.Run("invalid tmpl", func(t *testing.T) {
		ctx := buildCtx("none")
		ctx.Config.Blobs = []config.Blob{{
			Provider: "s3",
			Bucket:   name,
			Endpoint: "http://" + listen,
			Disable:  `{{ .Env.NOME }}`,
		}}
		require.NoError(t, Pipe{}.Default(ctx))
		testlib.RequireTemplateError(t, Pipe{}.Publish(ctx))
	})
}

func prepareEnv() {
	os.Setenv("AWS_ACCESS_KEY_ID", minioUser)
	os.Setenv("AWS_SECRET_ACCESS_KEY", minioPwd)
	os.Setenv("AWS_REGION", "us-east-1")
}

func minioClient() *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://" + listen),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(minioUser, minioPwd, ""),
	})
}

func setupBucket(tb testing.TB, name string) {
	tb.Helper()

	client := minioClient()
	_, err := client.CreateBucket(tb.Context(), &s3.CreateBucketInput{Bucket: aws.String(name)})
	require.NoError(tb, err)
}

// putForeignObject writes an object without any GoReleaser metadata,
// simulating a manual upload.
func putForeignObject(tb testing.TB, client *s3.Client, bucket, key string, body []byte) {
	tb.Helper()
	_, err := client.PutObject(tb.Context(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	})
	require.NoError(tb, err)
}

func getObject(tb testing.TB, client *s3.Client, bucket, key string) []byte {
	tb.Helper()
	out, err := client.GetObject(tb.Context(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(tb, err)
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	require.NoError(tb, err)
	return body
}

func headObject(tb testing.TB, client *s3.Client, bucket, key string) *s3.HeadObjectOutput {
	tb.Helper()
	out, err := client.HeadObject(tb.Context(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(tb, err)
	return out
}

// listUploadsForKey returns in-progress multipart uploads for the exact key.
func listUploadsForKey(tb testing.TB, client *s3.Client, bucket, key string) []string {
	tb.Helper()
	var ids []string
	out, err := client.ListMultipartUploads(tb.Context(), &s3.ListMultipartUploadsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String(key),
	})
	require.NoError(tb, err)
	for _, up := range out.Uploads {
		if aws.ToString(up.Key) == key {
			ids = append(ids, aws.ToString(up.UploadId))
		}
	}
	return ids
}

// withMinioPartTuning lowers the multipart part size to MinIO's 5MiB minimum
// so tests do not need to upload huge files.
func withMinioPartTuning(tb testing.TB) {
	tb.Helper()
	prevSize, prevThreshold, prevConc := s3PartSize, s3MultipartThreshold, s3PartConcurrency
	prevWrap := s3WrapTransport
	s3PartSize = 5 << 20
	s3MultipartThreshold = 4 << 20
	s3PartConcurrency = 2
	tb.Cleanup(func() {
		s3PartSize, s3MultipartThreshold, s3PartConcurrency = prevSize, prevThreshold, prevConc
		s3WrapTransport = prevWrap
	})
}

func deterministicBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)*31 + seed
	}
	return out
}

func sha256Hex(tb testing.TB, body []byte) string {
	tb.Helper()
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func largeBlobConfig(bucket string) config.Blob {
	return config.Blob{
		Provider: "s3",
		Bucket:   bucket,
		Region:   "us-east-1",
		Endpoint: "http://" + listen,
	}
}

func TestMinioResumableUpload(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	withMinioPartTuning(t)

	name := "resumable"
	setupBucket(t, name)
	client := minioClient()

	body := deterministicBytes(12<<20, 0x5a)
	srcpath := filepath.Join(t.TempDir(), "big.bin")
	require.NoError(t, os.WriteFile(srcpath, body, 0o644))

	publish := func() *context.Context {
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			ProjectName: "testupload",
			Blobs:       []config.Blob{largeBlobConfig(name)},
		}, testctx.WithCurrentTag("v1.0.0"))
		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.UploadableArchive,
			Name: "big.bin",
			Path: srcpath,
		})
		require.NoError(t, Pipe{}.Default(ctx))
		return ctx
	}

	key := "testupload/v1.0.0/big.bin"

	require.NoError(t, Pipe{}.Publish(publish()))
	require.Empty(t, listUploadsForKey(t, client, name, key))
	require.Equal(t, body, getObject(t, client, name, key))
	head := headObject(t, client, name, key)
	require.Equal(t, "sha256:"+sha256Hex(t, body), head.Metadata[s3ChecksumMetadata])

	// a re-run reuses the identical object and leaves no unfinished uploads.
	require.NoError(t, Pipe{}.Publish(publish()))
	require.Empty(t, listUploadsForKey(t, client, name, key))
	require.Equal(t, body, getObject(t, client, name, key))
}

func TestMinioResumeAfterInterruption(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	withMinioPartTuning(t)

	name := "resumable-interrupted"
	setupBucket(t, name)
	client := minioClient()

	body := deterministicBytes(12<<20, 0xa5) // parts: 5MiB, 5MiB, 2MiB
	srcpath := filepath.Join(t.TempDir(), "big.bin")
	require.NoError(t, os.WriteFile(srcpath, body, 0o644))

	buildCtx := func() *context.Context {
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			ProjectName: "testupload",
			Blobs:       []config.Blob{largeBlobConfig(name)},
		}, testctx.WithCurrentTag("v1.0.0"))
		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.UploadableArchive,
			Name: "big.bin",
			Path: srcpath,
		})
		require.NoError(t, Pipe{}.Default(ctx))
		return ctx
	}
	key := "testupload/v1.0.0/big.bin"

	// fail every part but the first, as a network drop would.
	s3WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return failingUploadPartsTransport{
			next:     next,
			failFrom: 2,
		}
	}
	err := Pipe{}.Publish(buildCtx())
	require.Error(t, err)
	require.Contains(t, err.Error(), "simulated network interruption")
	ids := listUploadsForKey(t, client, name, key)
	require.Len(t, ids, 1, "the interrupted multipart upload stays for resume")

	// network is back: resume and converge.
	s3WrapTransport = nil
	require.NoError(t, Pipe{}.Publish(buildCtx()))
	require.Empty(t, listUploadsForKey(t, client, name, key), "no unfinished uploads remain")
	require.Equal(t, body, getObject(t, client, name, key))
}

type failingUploadPartsTransport struct {
	next     http.RoundTripper
	failFrom int32
}

func (t failingUploadPartsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPut && req.URL.Query().Get("partNumber") != "" {
		var num int32
		if _, err := fmt.Sscanf(req.URL.Query().Get("partNumber"), "%d", &num); err == nil && num >= t.failFrom {
			return nil, fmt.Errorf("simulated network interruption uploading part %d", num)
		}
	}
	return t.next.RoundTrip(req)
}

func TestMinioManualObjectIsNotOverwritten(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	withMinioPartTuning(t)

	name := "resumable-manual"
	setupBucket(t, name)
	client := minioClient()

	key := "testupload/v1.0.0/big.bin"
	putForeignObject(t, client, name, key, []byte("hand uploaded"))

	body := deterministicBytes(12<<20, 0x33)
	srcpath := filepath.Join(t.TempDir(), "big.bin")
	require.NoError(t, os.WriteFile(srcpath, body, 0o644))

	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		ProjectName: "testupload",
		Blobs:       []config.Blob{largeBlobConfig(name)},
	}, testctx.WithCurrentTag("v1.0.0"))
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "big.bin",
		Path: srcpath,
	})
	require.NoError(t, Pipe{}.Default(ctx))

	err := Pipe{}.Publish(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to overwrite")
	require.Equal(t, []byte("hand uploaded"), getObject(t, client, name, key), "manual bytes must remain untouched")
	require.Empty(t, listUploadsForKey(t, client, name, key), "no multipart upload must be started")
}

func TestMinioOtherPrefixesAreUnaffected(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	withMinioPartTuning(t)

	name := "resumable-prefixes"
	setupBucket(t, name)
	client := minioClient()

	// unrelated object and an in-progress upload under a sibling key.
	putForeignObject(t, client, name, "testupload/v1.0.0/other.txt", []byte("keep"))
	created, err := client.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{
		Bucket: aws.String(name),
		Key:    aws.String("testupload/v1.0.0/other.bin"),
	})
	require.NoError(t, err)
	part := deterministicBytes(5<<20, 0x77)
	_, err = client.UploadPart(t.Context(), &s3.UploadPartInput{
		Bucket:     aws.String(name),
		Key:        aws.String("testupload/v1.0.0/other.bin"),
		UploadId:   created.UploadId,
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader(part),
	})
	require.NoError(t, err)

	body := deterministicBytes(12<<20, 0x11)
	srcpath := filepath.Join(t.TempDir(), "big.bin")
	require.NoError(t, os.WriteFile(srcpath, body, 0o644))

	ctx := testctx.WrapWithCfg(t.Context(), config.Project{
		ProjectName: "testupload",
		Blobs:       []config.Blob{largeBlobConfig(name)},
	}, testctx.WithCurrentTag("v1.0.0"))
	ctx.Artifacts.Add(&artifact.Artifact{
		Type: artifact.UploadableArchive,
		Name: "big.bin",
		Path: srcpath,
	})
	require.NoError(t, Pipe{}.Default(ctx))
	require.NoError(t, Pipe{}.Publish(ctx))

	require.Equal(t, []byte("keep"), getObject(t, client, name, "testupload/v1.0.0/other.txt"))
	require.Len(t, listUploadsForKey(t, client, name, "testupload/v1.0.0/other.bin"), 1)
	require.Empty(t, listUploadsForKey(t, client, name, "testupload/v1.0.0/big.bin"))
}

func TestMinioChangedContentReplacesOwnObject(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")
	withMinioPartTuning(t)

	name := "resumable-changed"
	setupBucket(t, name)
	client := minioClient()

	srcpath := filepath.Join(t.TempDir(), "big.bin")
	key := "testupload/v1.0.0/big.bin"

	publish := func() *context.Context {
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			ProjectName: "testupload",
			Blobs:       []config.Blob{largeBlobConfig(name)},
		}, testctx.WithCurrentTag("v1.0.0"))
		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.UploadableArchive,
			Name: "big.bin",
			Path: srcpath,
		})
		require.NoError(t, Pipe{}.Default(ctx))
		return ctx
	}

	v1 := deterministicBytes(12<<20, 0x01)
	require.NoError(t, os.WriteFile(srcpath, v1, 0o644))
	require.NoError(t, Pipe{}.Publish(publish()))

	// simulate a stale in-progress upload for the old content left behind.
	_, err := client.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{
		Bucket: aws.String(name),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	require.Len(t, listUploadsForKey(t, client, name, key), 1)

	v2 := deterministicBytes(12<<20, 0x02)
	require.NoError(t, os.WriteFile(srcpath, v2, 0o644))
	require.NoError(t, Pipe{}.Publish(publish()))

	require.Equal(t, v2, getObject(t, client, name, key))
	require.Empty(t, listUploadsForKey(t, client, name, key), "the stale upload and any duplicates must be cleaned up")
	head := headObject(t, client, name, key)
	require.Equal(t, "sha256:"+sha256Hex(t, v2), head.Metadata[s3ChecksumMetadata])
}

func TestMinioSmallObjectUpload(t *testing.T) {
	testlib.CheckDocker(t)
	testlib.SkipIfWindows(t, "minio image not available for windows")

	name := "resumable-small"
	setupBucket(t, name)
	client := minioClient()

	body := []byte("tiny release artifact")
	srcpath := filepath.Join(t.TempDir(), "small.txt")
	require.NoError(t, os.WriteFile(srcpath, body, 0o644))

	publish := func() *context.Context {
		ctx := testctx.WrapWithCfg(t.Context(), config.Project{
			ProjectName: "testupload",
			Blobs:       []config.Blob{largeBlobConfig(name)},
		}, testctx.WithCurrentTag("v1.0.0"))
		ctx.Artifacts.Add(&artifact.Artifact{
			Type: artifact.UploadableArchive,
			Name: "small.txt",
			Path: srcpath,
		})
		require.NoError(t, Pipe{}.Default(ctx))
		return ctx
	}

	key := "testupload/v1.0.0/small.txt"
	require.NoError(t, Pipe{}.Publish(publish()))
	require.Equal(t, body, getObject(t, client, name, key))
	head := headObject(t, client, name, key)
	require.Equal(t, int64(len(body)), aws.ToInt64(head.ContentLength))
	require.Equal(t, "sha256:"+sha256Hex(t, body), head.Metadata[s3ChecksumMetadata])

	// re-running is a no-op even though the object is small.
	require.NoError(t, Pipe{}.Publish(publish()))
	require.Equal(t, body, getObject(t, client, name, key))
}

func getFiles(t *testing.T, ctx *context.Context, cfg config.Blob) []string {
	t.Helper()
	url, err := urlFor(ctx, cfg)
	require.NoError(t, err)
	conn, err := blob.OpenBucket(ctx, url)
	require.NoError(t, err)
	defer conn.Close()
	iter := conn.List(nil)
	var files []string
	for {
		file, err := iter.Next(ctx)
		if err != nil && err == io.EOF {
			break
		}
		require.NoError(t, err)
		files = append(files, file.Key)
	}
	return files
}
