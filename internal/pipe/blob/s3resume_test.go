package blob

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/goreleaser/goreleaser/v2/internal/testctx"
	"github.com/goreleaser/goreleaser/v2/pkg/config"
	"github.com/stretchr/testify/require"
)

// fakeS3 is an in-process simulation of the S3 operations the resumable
// uploader relies on.
type fakeS3 struct {
	mu sync.Mutex

	bucket  string
	objects map[string]*fakeObject
	uploads map[string]*fakeUpload

	seq int

	// hooks
	failUploadPart func(part int32) error
	failComplete   func() error
	failPut        error

	// counters
	puts              int
	creates           int
	completes         int
	aborts            int
	uploadPartCalls   map[int32]int
	putIfNoneMatchSet int
}

type fakeObject struct {
	data     []byte
	metadata map[string]string
	crc32    string
	etag     string
}

type fakeUpload struct {
	key       string
	metadata  map[string]string
	parts     map[int32]*fakePart
	initiated time.Time
}

type fakePart struct {
	data []byte
	crc  string
	etag string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{
		bucket:          "bucket",
		objects:         map[string]*fakeObject{},
		uploads:         map[string]*fakeUpload{},
		uploadPartCalls: map[int32]int{},
	}
}

func apiError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: code, Fault: smithy.FaultClient}
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, apiError("NotFound")
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(obj.data))),
		Metadata:      obj.metadata,
		ChecksumCRC32: aws.String(obj.crc32),
		ETag:          aws.String(obj.etag),
	}, nil
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.failPut != nil {
		return nil, f.failPut
	}
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := aws.ToString(in.Key)
	if aws.ToString(in.IfNoneMatch) == "*" {
		f.putIfNoneMatchSet++
		if _, ok := f.objects[key]; ok {
			return nil, apiError("PreconditionFailed")
		}
	}
	if in.IfMatch != nil {
		obj, ok := f.objects[key]
		if !ok || obj.etag != aws.ToString(in.IfMatch) {
			return nil, apiError("PreconditionFailed")
		}
	}
	f.puts++
	etag := `"` + md5hex(data) + `"`
	f.objects[key] = &fakeObject{
		data:     data,
		metadata: cloneMetadata(in.Metadata),
		crc32:    aws.ToString(in.ChecksumCRC32),
		etag:     etag,
	}
	return &s3.PutObjectOutput{ETag: aws.String(etag)}, nil
}

func (f *fakeS3) CreateMultipartUpload(_ context.Context, in *s3.CreateMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := fmt.Sprintf("upload-%d", f.seq)
	f.uploads[id] = &fakeUpload{
		key:       aws.ToString(in.Key),
		metadata:  cloneMetadata(in.Metadata),
		parts:     map[int32]*fakePart{},
		initiated: time.Now().Add(time.Duration(f.seq) * time.Minute),
	}
	f.creates++
	return &s3.CreateMultipartUploadOutput{UploadId: aws.String(id)}, nil
}

func (f *fakeS3) UploadPart(_ context.Context, in *s3.UploadPartInput, _ ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	num := aws.ToInt32(in.PartNumber)
	if f.failUploadPart != nil {
		if err := f.failUploadPart(num); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploadPartCalls[num]++
	up, ok := f.uploads[aws.ToString(in.UploadId)]
	if !ok {
		return nil, apiError("NoSuchUpload")
	}
	etag := `"` + md5hex(data) + `"`
	up.parts[num] = &fakePart{data: append([]byte(nil), data...), crc: aws.ToString(in.ChecksumCRC32), etag: etag}
	return &s3.UploadPartOutput{ETag: aws.String(etag), ChecksumCRC32: in.ChecksumCRC32}, nil
}

func (f *fakeS3) ListParts(_ context.Context, in *s3.ListPartsInput, _ ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	up, ok := f.uploads[aws.ToString(in.UploadId)]
	if !ok {
		return nil, apiError("NoSuchUpload")
	}
	var parts []s3types.Part
	for num, p := range up.parts {
		parts = append(parts, s3types.Part{
			PartNumber:    aws.Int32(num),
			Size:          aws.Int64(int64(len(p.data))),
			ETag:          aws.String(p.etag),
			ChecksumCRC32: aws.String(p.crc),
		})
	}
	sort.Slice(parts, func(i, j int) bool { return aws.ToInt32(parts[i].PartNumber) < aws.ToInt32(parts[j].PartNumber) })
	return &s3.ListPartsOutput{Parts: parts}, nil
}

func (f *fakeS3) ListMultipartUploads(_ context.Context, in *s3.ListMultipartUploadsInput, _ ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []s3types.MultipartUpload
	for id, up := range f.uploads {
		key := up.key
		if !bytes.HasPrefix([]byte(key), []byte(aws.ToString(in.Prefix))) {
			continue
		}
		t := up.initiated
		out = append(out, s3types.MultipartUpload{
			Key:               aws.String(key),
			UploadId:          aws.String(id),
			Initiated:         &t,
			ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc32,
		})
	}
	return &s3.ListMultipartUploadsOutput{Uploads: out}, nil
}

func (f *fakeS3) CompleteMultipartUpload(_ context.Context, in *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	if f.failComplete != nil {
		if err := f.failComplete(); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	up, ok := f.uploads[aws.ToString(in.UploadId)]
	if !ok {
		return nil, apiError("NoSuchUpload")
	}
	parts := in.MultipartUpload.Parts
	if len(parts) == 0 {
		return nil, apiError("InvalidPart")
	}
	var data []byte
	for i, cp := range parts {
		num := int32(i + 1)
		if aws.ToInt32(cp.PartNumber) != num {
			return nil, apiError("InvalidPart")
		}
		p, ok := up.parts[num]
		if !ok {
			return nil, apiError("InvalidPart")
		}
		data = append(data, p.data...)
	}
	if aws.ToString(in.IfNoneMatch) == "*" {
		if _, exists := f.objects[up.key]; exists {
			return nil, apiError("PreconditionFailed")
		}
	}
	if in.IfMatch != nil {
		obj, ok := f.objects[up.key]
		if !ok || obj.etag != aws.ToString(in.IfMatch) {
			return nil, apiError("PreconditionFailed")
		}
	}
	f.completes++
	etag := `"` + md5hex(data) + `"`
	f.objects[up.key] = &fakeObject{data: data, metadata: cloneMetadata(up.metadata), etag: etag}
	delete(f.uploads, aws.ToString(in.UploadId))
	return &s3.CompleteMultipartUploadOutput{ETag: aws.String(etag), Key: aws.String(up.key)}, nil
}

func (f *fakeS3) AbortMultipartUpload(_ context.Context, in *s3.AbortMultipartUploadInput, _ ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.uploads[aws.ToString(in.UploadId)]; !ok {
		return nil, apiError("NoSuchUpload")
	}
	delete(f.uploads, aws.ToString(in.UploadId))
	f.aborts++
	return &s3.AbortMultipartUploadOutput{}, nil
}

func (f *fakeS3) putForeignObject(key string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = &fakeObject{data: data, metadata: map[string]string{"owner": "someone-else"}}
}

func (f *fakeS3) object(key string) (*fakeObject, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.objects[key]
	return o, ok
}

func (f *fakeS3) startUpload(key, checksum string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := fmt.Sprintf("upload-%d", f.seq)
	f.uploads[id] = &fakeUpload{
		key: key,
		metadata: map[string]string{
			s3ChecksumMetadata: checksum,
		},
		parts:     map[int32]*fakePart{},
		initiated: time.Now().Add(time.Duration(f.seq) * time.Minute),
	}
	return id
}

func (f *fakeS3) addPart(id string, num int32, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	crc := base64.StdEncoding.EncodeToString(crc32Sum(crc32.NewIEEE(), data).Sum(nil))
	etag := `"` + md5hex(data) + `"`
	f.uploads[id].parts[num] = &fakePart{data: data, crc: crc, etag: etag}
}

func cloneMetadata(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func md5hex(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])
}

func patternBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)*31 + seed
	}
	return out
}

func checksumValue(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// withTestTuning overrides multipart tuning for the duration of the test.
func withTestTuning(t *testing.T, partSize, threshold int64) {
	t.Helper()
	prevSize, prevThreshold, prevConc := s3PartSize, s3MultipartThreshold, s3PartConcurrency
	s3PartSize = partSize
	s3MultipartThreshold = threshold
	s3PartConcurrency = 4
	t.Cleanup(func() {
		s3PartSize, s3MultipartThreshold, s3PartConcurrency = prevSize, prevThreshold, prevConc
	})
}

func newTestUploader(f *fakeS3) *s3ResumableUploader {
	return &s3ResumableUploader{bucket: f.bucket, client: f}
}

func writeTestFile(t *testing.T, data []byte) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "artifact.bin")
	require.NoError(t, os.WriteFile(file, data, 0o644))
	return file
}

func TestS3SmallUploadFirstTimeAndReuse(t *testing.T) {
	withTestTuning(t, 1<<20, 1<<20)
	f := newFakeS3()
	u := newTestUploader(f)
	file := writeTestFile(t, []byte("hello world"))
	ctx := testctx.Wrap(t.Context())

	require.NoError(t, u.UploadFile(ctx, "dir/a.txt", file))
	require.Equal(t, 1, f.puts)
	require.Equal(t, 1, f.putIfNoneMatchSet, "first upload must guard against concurrent writes")

	obj, ok := f.object("dir/a.txt")
	require.True(t, ok)
	require.Equal(t, []byte("hello world"), obj.data)
	require.Equal(t, checksumValue([]byte("hello world")), obj.metadata[s3ChecksumMetadata])
	require.NotEmpty(t, obj.crc32)

	// re-run with identical content: nothing is uploaded again.
	require.NoError(t, u.UploadFile(ctx, "dir/a.txt", file))
	require.Equal(t, 1, f.puts)
	require.Zero(t, len(f.uploads))
}

func TestS3ManualObjectIsNotOverwritten(t *testing.T) {
	t.Run("small", func(t *testing.T) {
		withTestTuning(t, 1<<20, 1<<20)
		f := newFakeS3()
		u := newTestUploader(f)
		file := writeTestFile(t, []byte("new content"))
		f.putForeignObject("dir/a.txt", []byte("manual"))

		var conflict *ErrManualObject
		err := u.UploadFile(testctx.Wrap(t.Context()), "dir/a.txt", file)
		require.ErrorAs(t, err, &conflict)
		require.Equal(t, 0, f.puts)
		obj, _ := f.object("dir/a.txt")
		require.Equal(t, []byte("manual"), obj.data)
	})

	t.Run("multipart", func(t *testing.T) {
		withTestTuning(t, 100, 100)
		f := newFakeS3()
		u := newTestUploader(f)
		file := writeTestFile(t, patternBytes(250, 1))
		f.putForeignObject("dir/a.bin", []byte("manual"))

		var conflict *ErrManualObject
		err := u.UploadFile(testctx.Wrap(t.Context()), "dir/a.bin", file)
		require.ErrorAs(t, err, &conflict)
		require.Equal(t, 0, f.creates)
		obj, _ := f.object("dir/a.bin")
		require.Equal(t, []byte("manual"), obj.data)
	})
}

func TestS3OwnObjectWithChangedContentIsReplaced(t *testing.T) {
	withTestTuning(t, 1<<20, 1<<20)
	f := newFakeS3()
	u := newTestUploader(f)
	newData := []byte("new content")
	file := writeTestFile(t, newData)

	// our marker, but an older digest.
	f.objects["dir/a.txt"] = &fakeObject{
		data:     []byte("old content"),
		metadata: map[string]string{s3ChecksumMetadata: "sha256:deadbeef"},
		etag:     `"` + md5hex([]byte("old content")) + `"`,
	}

	require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), "dir/a.txt", file))
	require.Equal(t, 1, f.puts)
	require.Zero(t, f.putIfNoneMatchSet, "replacing our own object must not use If-None-Match")
	obj, _ := f.object("dir/a.txt")
	require.Equal(t, newData, obj.data)
	require.Equal(t, checksumValue(newData), obj.metadata[s3ChecksumMetadata])
}

func TestS3MultipartResumeAfterInterruption(t *testing.T) {
	withTestTuning(t, 100, 100)
	data := patternBytes(250, 7)
	file := writeTestFile(t, data)
	key := "dir/a.bin"

	t.Run("interrupted upload leaves resumable state", func(t *testing.T) {
		f := newFakeS3()
		u := newTestUploader(f)
		// everything from part 2 onwards fails, simulating a network drop.
		f.failUploadPart = func(num int32) error {
			if num >= 2 {
				return errors.New("simulated network interruption")
			}
			return nil
		}
		err := u.UploadFile(testctx.Wrap(t.Context()), key, file)
		require.Error(t, err)
		require.Contains(t, err.Error(), "simulated network interruption")

		require.Equal(t, 1, f.creates)
		require.Equal(t, 0, f.completes)
		require.Len(t, f.uploads, 1, "the unfinished multipart upload must remain for resume")
		require.Equal(t, 1, f.uploadPartCalls[1])
	})

	t.Run("rerun resumes and converges", func(t *testing.T) {
		f := newFakeS3()
		u := newTestUploader(f)

		// seed the interrupted run's state: part 1 already uploaded.
		id := f.startUpload(key, checksumValue(data))
		f.addPart(id, 1, data[:100])
		// an upload that no longer corresponds to this content.
		stale := f.startUpload(key, "sha256:different")
		f.addPart(stale, 1, patternBytes(200, 99))

		require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), key, file))

		require.Zero(t, f.creates, "must reuse the existing upload, not start a new one")
		require.Equal(t, 1, f.aborts, "the stale layout upload must be aborted")
		require.Zero(t, f.uploadPartCalls[1], "matching part 1 is not uploaded again")
		require.GreaterOrEqual(t, f.uploadPartCalls[2], 1)
		require.GreaterOrEqual(t, f.uploadPartCalls[3], 1)
		require.Equal(t, 1, f.completes)
		require.Empty(t, f.uploads, "all unfinished uploads for this key converge away")

		obj, ok := f.object(key)
		require.True(t, ok)
		require.Equal(t, data, obj.data)
		require.Equal(t, checksumValue(data), obj.metadata[s3ChecksumMetadata])
	})

	t.Run("rerun twice is stable", func(t *testing.T) {
		f := newFakeS3()
		u := newTestUploader(f)
		id := f.startUpload(key, checksumValue(data))
		f.addPart(id, 1, data[:100])

		for i := 0; i < 2; i++ {
			require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), key, file))
		}
		require.Zero(t, f.creates)
		require.Equal(t, 1, f.completes)
		obj, _ := f.object(key)
		require.Equal(t, data, obj.data)
	})
}

func TestS3ChangedPartIsReuploaded(t *testing.T) {
	withTestTuning(t, 100, 100)
	data := patternBytes(250, 3)
	f := newFakeS3()
	u := newTestUploader(f)
	key := "dir/a.bin"

	id := f.startUpload(key, checksumValue(data))
	// layout-compatible, but part 1 carries different bytes.
	f.addPart(id, 1, patternBytes(100, 42))
	f.addPart(id, 2, data[100:200])

	require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), key, writeTestFile(t, data)))
	require.Equal(t, 1, f.uploadPartCalls[1], "corrupt part must be re-uploaded")
	require.Equal(t, 0, f.uploadPartCalls[2], "matching part must be reused")
	require.Equal(t, 1, f.uploadPartCalls[3])
	obj, _ := f.object(key)
	require.Equal(t, data, obj.data)
}

func TestS3IncompatibleLayoutIsRebuilt(t *testing.T) {
	withTestTuning(t, 100, 100)
	data := patternBytes(250, 5)
	f := newFakeS3()
	u := newTestUploader(f)
	key := "dir/a.bin"

	stale := f.startUpload(key, "sha256:different")
	// 200-byte parts cannot match the new 100-byte layout.
	f.addPart(stale, 1, patternBytes(200, 9))

	require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), key, writeTestFile(t, data)))
	require.Equal(t, 1, f.aborts)
	require.Equal(t, 1, f.creates)
	obj, _ := f.object(key)
	require.Equal(t, data, obj.data)
}

func TestS3DuplicateUploadsConvergeToOne(t *testing.T) {
	withTestTuning(t, 100, 100)
	data := patternBytes(250, 11)
	f := newFakeS3()
	u := newTestUploader(f)
	key := "dir/a.bin"

	// two empty uploads from crashed runs: nothing identifiable to resume,
	// so both are aborted and a fresh, marked upload is created.
	f.startUpload(key, checksumValue(data))
	f.startUpload(key, checksumValue(data))

	require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), key, writeTestFile(t, data)))
	require.Empty(t, f.uploads)
	require.Equal(t, 2, f.aborts)
	require.Equal(t, 1, f.creates)
	require.Equal(t, 1, f.completes)
	obj, _ := f.object(key)
	require.Equal(t, data, obj.data)
}

func TestS3OtherPrefixesAreUntouched(t *testing.T) {
	withTestTuning(t, 100, 100)
	data := patternBytes(250, 13)
	f := newFakeS3()
	u := newTestUploader(f)
	f.putForeignObject("other/manual.txt", []byte("keep me"))
	otherUpload := f.startUpload("other/in-progress.bin", "sha256:other")
	f.addPart(otherUpload, 1, patternBytes(100, 13))

	require.NoError(t, u.UploadFile(testctx.Wrap(t.Context()), "dir/a.bin", writeTestFile(t, data)))

	obj, ok := f.object("other/manual.txt")
	require.True(t, ok)
	require.Equal(t, []byte("keep me"), obj.data)
	require.Contains(t, f.uploads, otherUpload, "unrelated multipart upload must not be aborted")
}

func TestS3SmallPutPreconditionFailedBecomesConflict(t *testing.T) {
	withTestTuning(t, 1<<20, 1<<20)
	f := newFakeS3()
	u := newTestUploader(f)
	file := writeTestFile(t, []byte("new"))
	// HeadObject reported the key as absent, but a manual object appeared
	// before the PutObject landed: S3 answers with 412.
	f.failPut = apiError("PreconditionFailed")

	var conflict *ErrManualObject
	require.ErrorAs(t, u.UploadFile(testctx.Wrap(t.Context()), "dir/a.txt", file), &conflict)
	require.Equal(t, 0, f.puts)
}

func TestS3StaleObjectSwappedManuallyBecomesConflict(t *testing.T) {
	withTestTuning(t, 1<<20, 1<<20)
	f := newFakeS3()
	u := newTestUploader(f)
	file := writeTestFile(t, []byte("new content"))
	// our old object, still visible during HeadObject...
	f.objects["dir/a.txt"] = &fakeObject{
		data:     []byte("old content"),
		metadata: map[string]string{s3ChecksumMetadata: "sha256:deadbeef"},
		etag:     `"old-etag"`,
	}
	// ...but it is replaced by a manual object before our conditional write.
	f.failPut = apiError("PreconditionFailed")

	var conflict *ErrManualObject
	require.ErrorAs(t, u.UploadFile(testctx.Wrap(t.Context()), "dir/a.txt", file), &conflict)
	require.Equal(t, 0, f.puts)
}

func TestS3MultipartCompletePreconditionFailedBecomesConflict(t *testing.T) {
	withTestTuning(t, 100, 100)
	f := newFakeS3()
	u := newTestUploader(f)
	data := patternBytes(250, 17)
	file := writeTestFile(t, data)
	// A manual object with the same key appears while we were uploading.
	f.failComplete = func() error {
		f.putForeignObject("dir/a.bin", []byte("manual"))
		return apiError("PreconditionFailed")
	}

	var conflict *ErrManualObject
	require.ErrorAs(t, u.UploadFile(testctx.Wrap(t.Context()), "dir/a.bin", file), &conflict)
	require.Equal(t, 1, f.aborts, "our own upload must be aborted, the manual object kept")
	obj, _ := f.object("dir/a.bin")
	require.Equal(t, []byte("manual"), obj.data)
}

func TestLayoutMatches(t *testing.T) {
	part := func(num int32, size int64) s3types.Part {
		return s3types.Part{PartNumber: aws.Int32(num), Size: aws.Int64(size)}
	}
	// 250 bytes in 100-byte parts: 100, 100, 50.
	require.True(t, layoutMatches(nil, 250, 100, 3))
	require.True(t, layoutMatches([]s3types.Part{part(1, 100), part(3, 50)}, 250, 100, 3))
	require.False(t, layoutMatches([]s3types.Part{part(1, 200)}, 250, 100, 3), "different part size")
	require.False(t, layoutMatches([]s3types.Part{part(4, 1)}, 250, 100, 3), "part beyond expected count")
	require.False(t, layoutMatches([]s3types.Part{part(2, 99)}, 250, 100, 3), "wrong size for middle part")
	require.False(t, layoutMatches([]s3types.Part{part(3, 49)}, 250, 100, 3), "wrong size for last part")
}

func TestNormalizeEndpoint(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		disable  bool
		want     string
	}{
		{"", false, ""},
		{"s3.example.com", false, "https://s3.example.com"},
		{"s3.example.com", true, "http://s3.example.com"},
		{"https://s3.example.com", true, "http://s3.example.com"},
		{"http://localhost:9000", false, "http://localhost:9000"},
		{"https://s3.example.com", false, "https://s3.example.com"},
	} {
		require.Equal(t, tc.want, normalizeEndpoint(tc.endpoint, tc.disable), tc.endpoint)
	}
}

func TestInvalidACLIsRejected(t *testing.T) {
	up := newS3ResumableUploader(config.Blob{ACL: "not-an-acl"})
	require.EqualError(t, up.(fileUploader).UploadFile(testctx.Wrap(t.Context()), "k", "f"), `invalid ACL "not-an-acl"`)
}
