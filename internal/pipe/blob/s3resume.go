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
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/caarlos0/log"
	"github.com/goreleaser/goreleaser/v2/internal/tmpl"
	gcontext "github.com/goreleaser/goreleaser/v2/pkg/context"
)

// s3ChecksumMetadata is set on every object GoReleaser uploads to S3. Its
// value is "sha256:<hex>" of the uploaded content. It lets re-runs reuse an
// identical completed object and distinguishes GoReleaser managed objects from
// objects uploaded by other means, which must never be overwritten.
const s3ChecksumMetadata = "goreleaser-checksum"

var (
	// s3MultipartThreshold is the size above which a resumable multipart
	// upload is used. Smaller files are sent with a single PutObject, exactly
	// as first-time small uploads always were.
	s3MultipartThreshold int64 = 8 << 20 // 8 MiB
	// s3PartSize is the part size for multipart uploads. It must stay above
	// S3's 5 MiB minimum for non-final parts.
	s3PartSize int64 = 8 << 20 // 8 MiB
	// s3PartConcurrency bounds how many parts are uploaded in parallel for a
	// single object.
	s3PartConcurrency = 4

	// s3WrapTransport, when non-nil, decorates the HTTP transport of the S3
	// client. It exists for tests; production code leaves it nil.
	s3WrapTransport func(http.RoundTripper) http.RoundTripper
)

// fileUploader is implemented by uploaders that can take ownership of a local
// file path, for example to seek, hash and resume uploads. Uploaders that only
// consume a stream keep using Upload.
type fileUploader interface {
	UploadFile(ctx *gcontext.Context, key, filePath string) error
}

// s3API is the subset of the S3 client used by the resumable uploader. *s3.Client
// satisfies it, and tests provide a fake implementation.
type s3API interface {
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListMultipartUploads(ctx context.Context, in *s3.ListMultipartUploadsInput, opts ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error)
	ListParts(ctx context.Context, in *s3.ListPartsInput, opts ...func(*s3.Options)) (*s3.ListPartsOutput, error)
	CreateMultipartUpload(ctx context.Context, in *s3.CreateMultipartUploadInput, opts ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, in *s3.UploadPartInput, opts ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, in *s3.CompleteMultipartUploadInput, opts ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, in *s3.AbortMultipartUploadInput, opts ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
}

// ErrManualObject is returned when the destination key already holds an object
// that GoReleaser did not upload. It is never retried by overwriting.
type ErrManualObject struct {
	Bucket string
	Key    string
}

func (e *ErrManualObject) Error() string {
	return fmt.Sprintf(
		"refusing to overwrite s3://%s/%s: an object with the same key already exists but was not uploaded by GoReleaser (missing %q metadata); delete or rename it manually to continue",
		e.Bucket, e.Key, s3ChecksumMetadata)
}

// s3ResumableUploader uploads to S3-compatible storage with resumable multipart
// uploads keyed by bucket, object key and content digest.
type s3ResumableUploader struct {
	bucket string
	client s3API

	acl                s3types.ObjectCannedACL
	cacheControl       []string
	contentDisposition string
}

func (u *s3ResumableUploader) Close() error { return nil }

// Upload is part of the uploader interface. S3 uploads need a seekable local
// file to be hashed and resumed, so they go through UploadFile; a plain stream
// cannot be uploaded this way.
func (u *s3ResumableUploader) Upload(*gcontext.Context, string, io.Reader) error {
	return errors.New("s3 upload requires a seekable file")
}

func (u *s3ResumableUploader) Open(gctx *gcontext.Context, bucketURL string) error {
	log.WithField("bucket", bucketURL).Debug("uploading")

	u0, err := url.Parse(bucketURL)
	if err != nil {
		return err
	}
	if u0.Host == "" {
		return fmt.Errorf("invalid s3 bucket url %q", bucketURL)
	}
	u.bucket = u0.Host

	query := u0.Query()
	region := query.Get("region")
	endpoint := normalizeEndpoint(query.Get("endpoint"), query.Get("disable_https") == "true")
	forcePathStyle := query.Get("s3ForcePathStyle") == "true"
	if query.Get("s3ForcePathStyle") == "" && endpoint != "" {
		// urlFor defaults to path style when a custom endpoint is configured.
		forcePathStyle = true
	}

	cfg, err := awsconfig.LoadDefaultConfig(gctx, awsconfig.WithRegion(region))
	if err != nil {
		return err
	}
	u.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = forcePathStyle
		if s3WrapTransport != nil {
			transport := http.RoundTripper(http.DefaultTransport)
			if hc, ok := o.HTTPClient.(*http.Client); ok && hc.Transport != nil {
				transport = hc.Transport
			}
			o.HTTPClient = &http.Client{Transport: s3WrapTransport(transport)}
		}
	})
	return nil
}

func normalizeEndpoint(endpoint string, disableHTTPS bool) string {
	if endpoint == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(endpoint, "https://") && disableHTTPS:
		return "http://" + strings.TrimPrefix(endpoint, "https://")
	case strings.HasPrefix(endpoint, "http://"), strings.HasPrefix(endpoint, "https://"):
		return endpoint
	case disableHTTPS:
		return "http://" + endpoint
	default:
		return "https://" + endpoint
	}
}

// objectState classifies the object already present at the destination key.
type objectState int

const (
	objectAbsent  objectState = iota // no object exists
	objectCurrent                    // GoReleaser object with the expected digest
	objectStale                      // GoReleaser object with different content
	objectForeign                    // object uploaded by something else
)

// UploadFile uploads filePath to key, resuming or rebuilding an in-progress
// multipart upload when possible and never overwriting foreign objects.
func (u *s3ResumableUploader) UploadFile(gctx *gcontext.Context, key, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}
	size := fi.Size()

	sum, err := hashFile(f)
	if err != nil {
		return fmt.Errorf("failed to checksum file %s: %w", filePath, err)
	}
	checksumValue := "sha256:" + hex.EncodeToString(sum)

	headers, err := u.headers(gctx, key, f)
	if err != nil {
		return err
	}

	dst, err := u.classify(gctx, key, size, checksumValue)
	if err != nil {
		return err
	}
	switch dst.state {
	case objectCurrent:
		log.WithField("bucket", u.bucket).WithField("key", key).
			Info("object already uploaded with identical content, reusing")
		// A completed object is present, so any in-progress multipart upload
		// for this key no longer corresponds to anything: converge to the
		// single completed object.
		return u.abortUploadsForKey(gctx, key, "")
	case objectForeign:
		return &ErrManualObject{Bucket: u.bucket, Key: key}
	}

	log.WithField("bucket", u.bucket).WithField("key", key).Info("uploading")

	if size <= s3MultipartThreshold {
		return u.putSmall(gctx, key, f, size, checksumValue, headers, dst)
	}
	return u.uploadMultipart(gctx, key, f, size, checksumValue, headers, dst)
}

func (u *s3ResumableUploader) headers(gctx *gcontext.Context, key string, f *os.File) (s3ObjectHeaders, error) {
	disp, err := tmpl.New(gctx).WithExtraFields(tmpl.Fields{
		"Filename": path.Base(key),
	}).Apply(u.contentDisposition)
	if err != nil {
		return s3ObjectHeaders{}, err
	}
	contentType := ""
	if head, rerr := io.ReadAll(io.LimitReader(f, 512)); rerr == nil {
		contentType = http.DetectContentType(head)
		if _, serr := f.Seek(0, io.SeekStart); serr != nil {
			return s3ObjectHeaders{}, serr
		}
	}
	return s3ObjectHeaders{
		contentType:        contentType,
		contentDisposition: disp,
		cacheControl:       strings.Join(u.cacheControl, ", "),
	}, nil
}

type s3ObjectHeaders struct {
	contentType        string
	contentDisposition string
	cacheControl       string
}

// destination describes what currently occupies the target key.
type destination struct {
	state objectState
	// etag is the ETag of an existing GoReleaser object, used to replace it
	// only if it has not changed meanwhile.
	etag string
}

// classify heads the destination key and decides what is already there.
func (u *s3ResumableUploader) classify(ctx context.Context, key string, size int64, checksumValue string) (destination, error) {
	out, err := u.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3ErrorCode(err, "NotFound") {
			return destination{state: objectAbsent}, nil
		}
		return destination{}, err
	}
	marker := out.Metadata[s3ChecksumMetadata]
	switch {
	case marker == checksumValue && aws.ToInt64(out.ContentLength) == size:
		return destination{state: objectCurrent, etag: aws.ToString(out.ETag)}, nil
	case strings.HasPrefix(marker, "sha256:"):
		return destination{state: objectStale, etag: aws.ToString(out.ETag)}, nil
	default:
		return destination{state: objectForeign}, nil
	}
}

// putSmall uploads an object with a single PutObject. This keeps first-time
// small object uploads compatible with the previous behavior.
func (u *s3ResumableUploader) putSmall(ctx context.Context, key string, f *os.File, size int64, checksumValue string, h s3ObjectHeaders, dst destination) error {
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if int64(len(data)) != size {
		return fmt.Errorf("file %s changed while uploading", key)
	}
	crc := base64.StdEncoding.EncodeToString(crc32Sum(crc32.NewIEEE(), data).Sum(nil))

	in := &s3.PutObjectInput{
		Bucket:             aws.String(u.bucket),
		Key:                aws.String(key),
		Body:               bytes.NewReader(data),
		ContentLength:      aws.Int64(int64(len(data))),
		ContentType:        nzString(h.contentType),
		ContentDisposition: nzString(h.contentDisposition),
		CacheControl:       nzString(h.cacheControl),
		ACL:                u.acl,
		ChecksumAlgorithm:  s3types.ChecksumAlgorithmCrc32,
		ChecksumCRC32:      aws.String(crc),
		Metadata: map[string]string{
			s3ChecksumMetadata: checksumValue,
		},
	}
	switch dst.state {
	case objectAbsent:
		// Guard against an object appearing concurrently, in particular a
		// manually uploaded one that was not there during the head call.
		in.IfNoneMatch = aws.String("*")
	case objectStale:
		// Replace our own previous object only if it is still the same one.
		in.IfMatch = nzString(dst.etag)
	}
	if _, err := u.client.PutObject(ctx, in); err != nil {
		if isS3ErrorCode(err, "PreconditionFailed") {
			return &ErrManualObject{Bucket: u.bucket, Key: key}
		}
		return err
	}
	return nil
}

// uploadMultipart resumes or creates a multipart upload and only makes the
// object visible by completing it after every part has been verified.
func (u *s3ResumableUploader) uploadMultipart(gctx context.Context, key string, f *os.File, size int64, checksumValue string, h s3ObjectHeaders, dst destination) error {
	n := int32((size + s3PartSize - 1) / s3PartSize)

	uploadID, remoteParts, err := u.planUpload(gctx, key, size, n)
	if err != nil {
		return err
	}
	if uploadID == "" {
		out, err := u.client.CreateMultipartUpload(gctx, &s3.CreateMultipartUploadInput{
			Bucket:             aws.String(u.bucket),
			Key:                aws.String(key),
			ACL:                u.acl,
			ContentType:        nzString(h.contentType),
			ContentDisposition: nzString(h.contentDisposition),
			CacheControl:       nzString(h.cacheControl),
			ChecksumAlgorithm:  s3types.ChecksumAlgorithmCrc32,
			Metadata: map[string]string{
				s3ChecksumMetadata: checksumValue,
			},
		})
		if err != nil {
			return err
		}
		uploadID = aws.ToString(out.UploadId)
		log.WithField("bucket", u.bucket).WithField("key", key).WithField("upload_id", uploadID).
			Debug("started multipart upload")
	} else {
		log.WithField("bucket", u.bucket).
			WithField("key", key).
			WithField("upload_id", uploadID).
			WithField("parts_present", len(remoteParts)).
			WithField("parts_expected", n).
			Info("resuming multipart upload")
	}

	// Failed parts are kept on the server on purpose: the upload stays
	// resumable on the next run, while uploads that no longer correspond to
	// the local content are aborted during planUpload.
	completed, err := u.uploadParts(gctx, key, uploadID, f, size, n, remoteParts)
	if err != nil {
		return err
	}

	if err := u.complete(gctx, key, uploadID, size, checksumValue, completed, dst); err != nil {
		return err
	}

	if err := u.verify(gctx, key, size, checksumValue); err != nil {
		return err
	}

	// Any other in-progress upload for this key is now stale; converge to the
	// unique completed object.
	return u.abortUploadsForKey(gctx, key, uploadID)
}

// planUpload lists in-progress multipart uploads for key, aborts the ones that
// cannot correspond to the local content and returns the best reusable upload
// together with its parts.
func (u *s3ResumableUploader) planUpload(ctx context.Context, key string, size int64, n int32) (string, map[int32]s3types.Part, error) {
	uploads, err := u.listUploadsForKey(ctx, key)
	if err != nil {
		return "", nil, err
	}

	type candidate struct {
		uploadID  string
		parts     []s3types.Part
		initiated int64
	}
	var compatible []candidate
	for _, up := range uploads {
		parts, err := u.listParts(ctx, aws.ToString(up.UploadId), key)
		if err != nil {
			if isS3ErrorCode(err, "NoSuchUpload") {
				continue
			}
			return "", nil, err
		}
		// An upload without any parts carries no proof of who started it or
		// what content it belongs to (multipart upload metadata cannot be
		// read back), and resuming it would lose nothing. Abort and start a
		// fresh, identifiable upload.
		if len(parts) == 0 || !layoutMatches(parts, size, s3PartSize, n) {
			log.WithField("bucket", u.bucket).WithField("key", key).WithField("upload_id", aws.ToString(up.UploadId)).
				Info("aborting unidentifiable or incompatible multipart upload")
			if err := u.abort(ctx, key, aws.ToString(up.UploadId)); err != nil && !isS3ErrorCode(err, "NoSuchUpload") {
				return "", nil, err
			}
			continue
		}
		var initiated int64
		if up.Initiated != nil {
			initiated = up.Initiated.UnixNano()
		}
		compatible = append(compatible, candidate{
			uploadID:  aws.ToString(up.UploadId),
			parts:     parts,
			initiated: initiated,
		})
	}
	if len(compatible) == 0 {
		return "", map[int32]s3types.Part{}, nil
	}

	// Prefer the upload with the most parts already present, then the oldest
	// one so repeated runs make a deterministic choice.
	sort.Slice(compatible, func(i, j int) bool {
		if len(compatible[i].parts) != len(compatible[j].parts) {
			return len(compatible[i].parts) > len(compatible[j].parts)
		}
		if compatible[i].initiated != compatible[j].initiated {
			return compatible[i].initiated < compatible[j].initiated
		}
		return compatible[i].uploadID < compatible[j].uploadID
	})

	chosen := compatible[0]
	for _, c := range compatible[1:] {
		log.WithField("bucket", u.bucket).WithField("key", key).WithField("upload_id", c.uploadID).
			Info("aborting duplicate multipart upload")
		if err := u.abort(ctx, key, c.uploadID); err != nil && !isS3ErrorCode(err, "NoSuchUpload") {
			return "", nil, err
		}
	}

	remote := make(map[int32]s3types.Part, len(chosen.parts))
	for _, p := range chosen.parts {
		remote[aws.ToInt32(p.PartNumber)] = p
	}
	return chosen.uploadID, remote, nil
}

// layoutMatches reports whether every uploaded part has the number and size it
// would have for an upload of size bytes split into n parts of partSize.
func layoutMatches(parts []s3types.Part, size, partSize int64, n int32) bool {
	lastSize := size - int64(n-1)*partSize
	for _, p := range parts {
		num := aws.ToInt32(p.PartNumber)
		if num < 1 || num > n {
			return false
		}
		want := partSize
		if num == n {
			want = lastSize
		}
		if aws.ToInt64(p.Size) != want {
			return false
		}
	}
	return true
}

type partJob struct {
	num    int32
	data   []byte
	crc32  string
	md5hex string
}

// uploadParts sends the parts that are missing or no longer matching. Parts
// already present with identical bytes are not uploaded again.
func (u *s3ResumableUploader) uploadParts(ctx context.Context, key, uploadID string, f *os.File, size int64, n int32, remote map[int32]s3types.Part) ([]s3types.CompletedPart, error) {
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]s3types.CompletedPart, n)
	jobs := make(chan partJob, s3PartConcurrency)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
	}

	for w := 0; w < s3PartConcurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if pctx.Err() != nil {
					continue
				}
				if existing, ok := remote[job.num]; ok && partMatches(job, existing) {
					results[job.num-1] = s3types.CompletedPart{
						PartNumber:    aws.Int32(job.num),
						ETag:          existing.ETag,
						ChecksumCRC32: existing.ChecksumCRC32,
					}
					continue
				}
				out, err := u.client.UploadPart(pctx, &s3.UploadPartInput{
					Bucket:            aws.String(u.bucket),
					Key:               aws.String(key),
					UploadId:          aws.String(uploadID),
					PartNumber:        aws.Int32(job.num),
					Body:              bytes.NewReader(job.data),
					ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc32,
					ChecksumCRC32:     aws.String(job.crc32),
				})
				if err != nil {
					fail(fmt.Errorf("upload part %d/%d of s3://%s/%s: %w", job.num, n, u.bucket, key, err))
					continue
				}
				results[job.num-1] = s3types.CompletedPart{
					PartNumber:    aws.Int32(job.num),
					ETag:          out.ETag,
					ChecksumCRC32: aws.String(job.crc32),
				}
			}
		}()
	}

feed:
	for num := int32(1); num <= n; num++ {
		select {
		case <-pctx.Done():
			break feed
		default:
		}
		offset := int64(num-1) * s3PartSize
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			fail(err)
			break feed
		}
		length := s3PartSize
		if num == n {
			length = size - offset
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(f, data); err != nil {
			fail(err)
			break feed
		}
		crcH := crc32.NewIEEE()
		md5H := md5.New()
		_, _ = io.MultiWriter(crcH, md5H).Write(data)
		job := partJob{
			num:    num,
			data:   data,
			crc32:  base64.StdEncoding.EncodeToString(crcH.Sum(nil)),
			md5hex: hex.EncodeToString(md5H.Sum(nil)),
		}
		select {
		case jobs <- job:
		case <-pctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}

	sort.Slice(results, func(i, j int) bool {
		return aws.ToInt32(results[i].PartNumber) < aws.ToInt32(results[j].PartNumber)
	})
	for i, cp := range results {
		if cp.PartNumber == nil || aws.ToInt32(cp.PartNumber) != int32(i+1) || aws.ToString(cp.ETag) == "" {
			return nil, fmt.Errorf("incomplete multipart upload state for s3://%s/%s at part %d", u.bucket, key, i+1)
		}
	}
	return results, nil
}

// partMatches verifies that an already-uploaded part carries exactly the local
// bytes. CRC32 is used when the backend recorded it; otherwise the part ETag
// (MD5 of the part bytes) is compared.
func partMatches(job partJob, p s3types.Part) bool {
	if p.ChecksumCRC32 != nil {
		return aws.ToString(p.ChecksumCRC32) == job.crc32
	}
	return strings.Trim(aws.ToString(p.ETag), `"`) == job.md5hex
}

func (u *s3ResumableUploader) complete(ctx context.Context, key, uploadID string, size int64, checksumValue string, parts []s3types.CompletedPart, dst destination) error {
	in := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(u.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: parts,
		},
		MpuObjectSize: aws.Int64(size),
	}
	switch dst.state {
	case objectAbsent:
		// Do not become visible if a foreign object appeared meanwhile.
		in.IfNoneMatch = aws.String("*")
	case objectStale:
		// Only supersede our own previous object while it is unchanged.
		in.IfMatch = nzString(dst.etag)
	}
	if _, err := u.client.CompleteMultipartUpload(ctx, in); err != nil {
		if isS3ErrorCode(err, "PreconditionFailed") {
			_ = u.abort(ctx, key, uploadID)
			return &ErrManualObject{Bucket: u.bucket, Key: key}
		}
		if isS3ErrorCode(err, "NoSuchUpload") {
			// A concurrent run may have completed (and thus consumed) the
			// same upload: the upload is finished either way if the object is
			// now correct.
			if current, cerr := u.classify(ctx, key, size, checksumValue); cerr == nil && current.state == objectCurrent {
				return nil
			}
		}
		return err
	}
	return nil
}

// verify confirms the completed object is the full, expected content before it
// is considered the final object.
func (u *s3ResumableUploader) verify(ctx context.Context, key string, size int64, checksumValue string) error {
	dst, err := u.classify(ctx, key, size, checksumValue)
	if err != nil {
		return err
	}
	if dst.state != objectCurrent {
		return fmt.Errorf("uploaded object s3://%s/%s failed verification (%s)", u.bucket, key, checksumValue)
	}
	return nil
}

func (u *s3ResumableUploader) abort(ctx context.Context, key, uploadID string) error {
	_, err := u.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(u.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
	return err
}

// abortUploadsForKey aborts every in-progress multipart upload for the exact
// key, except exceptUploadID. Other prefixes are never listed.
func (u *s3ResumableUploader) abortUploadsForKey(ctx context.Context, key, exceptUploadID string) error {
	uploads, err := u.listUploadsForKey(ctx, key)
	if err != nil {
		return err
	}
	for _, up := range uploads {
		id := aws.ToString(up.UploadId)
		if id == exceptUploadID {
			continue
		}
		log.WithField("bucket", u.bucket).WithField("key", key).WithField("upload_id", id).
			Info("aborting stale multipart upload")
		if err := u.abort(ctx, key, id); err != nil && !isS3ErrorCode(err, "NoSuchUpload") {
			return err
		}
	}
	return nil
}

func (u *s3ResumableUploader) listUploadsForKey(ctx context.Context, key string) ([]s3types.MultipartUpload, error) {
	var (
		uploads   []s3types.MultipartUpload
		keyMarker *string
		idMarker  *string
	)
	for {
		out, err := u.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         aws.String(u.bucket),
			Prefix:         aws.String(key),
			KeyMarker:      keyMarker,
			UploadIdMarker: idMarker,
		})
		if err != nil {
			return nil, err
		}
		for _, up := range out.Uploads {
			// Prefix is a prefix match: only the exact key belongs to this
			// upload, so other keys and prefixes are left untouched.
			if aws.ToString(up.Key) == key {
				uploads = append(uploads, up)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return uploads, nil
		}
		keyMarker = out.NextKeyMarker
		idMarker = out.NextUploadIdMarker
	}
}

func (u *s3ResumableUploader) listParts(ctx context.Context, uploadID, key string) ([]s3types.Part, error) {
	var parts []s3types.Part
	marker := aws.String("0")
	for {
		out, err := u.client.ListParts(ctx, &s3.ListPartsInput{
			Bucket:           aws.String(u.bucket),
			Key:              aws.String(key),
			UploadId:         aws.String(uploadID),
			PartNumberMarker: marker,
		})
		if err != nil {
			return nil, err
		}
		parts = append(parts, out.Parts...)
		if !aws.ToBool(out.IsTruncated) {
			return parts, nil
		}
		marker = out.NextPartNumberMarker
	}
}

func hashFile(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func crc32Sum(h hash.Hash32, data []byte) hash.Hash32 {
	_, _ = h.Write(data)
	return h
}

func nzString(v string) *string {
	if v == "" {
		return nil
	}
	return aws.String(v)
}

func isS3ErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == code
	}
	return false
}
