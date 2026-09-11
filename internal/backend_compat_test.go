package internal

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	. "github.com/kahing/goofys/api/common"
)

func compatBackend(t *testing.T, handler http.HandlerFunc, configure func(*S3Config)) *S3Backend {
	t.Helper()
	config := (&S3Config{RegionSet: true, Credentials: credentials.NewStaticCredentialsProvider("access", "secret", "token")}).Init()
	if configure != nil {
		configure(config)
	}
	server := httptest.NewUnstartedServer(handler)
	if config.SseC != "" {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	backend, err := NewS3("bucket", &FlagStorage{Endpoint: server.URL, HTTPTimeout: time.Second}, config)
	if err != nil {
		t.Fatal(err)
	}
	if config.SseC != "" {
		backend.awsConfig.HTTPClient = server.Client()
	}
	retryer := backend.awsConfig.Retryer
	backend.awsConfig.Retryer = func() aws.Retryer {
		return retry.AddWithMaxBackoffDelay(retryer(), time.Nanosecond)
	}
	backend.newS3()
	return backend
}

func TestS3CompatibilityHeadersMetadataAndCopy(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/bucket/a%20b%2Bc" {
			t.Errorf("path = %s", r.URL.EscapedPath())
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.Header.Get("User-Agent"), "goofys/") {
			t.Errorf("user agent = %q", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("x-amz-server-side-encryption-customer-key") != key {
			t.Errorf("SSE-C key = %q", r.Header.Get("x-amz-server-side-encryption-customer-key"))
		}
		w.Header().Set("x-amz-request-id", "request")
		w.Header().Set("x-amz-id-2", "host")
		switch r.Method {
		case "HEAD", "GET":
			if r.Header.Get("x-amz-request-payer") != "requester" {
				t.Error("missing requester pays")
			}
			w.Header().Set("ETag", "\"etag\"")
			w.Header().Set("Content-Length", "3")
			w.Header().Set("x-amz-meta-MiXeD", "value")
			if r.Method == "GET" {
				if r.Header.Get("Accept-Encoding") != "identity" || strings.Contains(r.Header.Get("Authorization"), "accept-encoding") {
					t.Error("GET encoding must be identity and unsigned")
				}
				if r.Header.Get("Range") != "bytes=1-3" {
					t.Errorf("range = %q", r.Header.Get("Range"))
				}
				io.WriteString(w, "abc")
			}
		case "PUT":
			if r.Header.Get("x-amz-copy-source") != "bucket%2Fa+b%2Bc" {
				t.Errorf("copy source = %q", r.Header.Get("x-amz-copy-source"))
			}
			if r.Header.Get("x-amz-storage-class") != "STANDARD" {
				t.Errorf("storage class = %q", r.Header.Get("x-amz-storage-class"))
			}
			if r.Header.Get("x-amz-copy-source-server-side-encryption-customer-key") != key {
				t.Error("missing copy SSE-C key")
			}
			io.WriteString(w, "<CopyObjectResult><ETag>\"etag\"</ETag></CopyObjectResult>")
		}
	}, func(c *S3Config) { c.SseC = key; c.RequesterPays = true; c.StorageClass = "STANDARD_IA" })
	head, err := backend.HeadBlob(&HeadBlobInput{Key: "a b+c"})
	if err != nil {
		t.Fatal(err)
	}
	if head.StorageClass != nil || aws.ToString(head.Metadata["mixed"]) != "value" || head.RequestId != "request: host" {
		t.Fatalf("head = %+v", head)
	}
	got, err := backend.GetBlob(&GetBlobInput{Key: "a b+c", Start: 1, Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(got.Body)
	got.Body.Close()
	if err != nil || string(body) != "abc" {
		t.Fatalf("body = %q, %v", body, err)
	}
	if _, err := backend.CopyBlob(&CopyBlobInput{Source: "a b+c", Destination: "a b+c"}); err != nil {
		t.Fatal(err)
	}
}

func TestS3CompatibilityRetriesAndMetadata(t *testing.T) {
	var attempts atomic.Int32
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "payload" {
			t.Errorf("body = %q", body)
		}
		digest := md5.Sum(body)
		if r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(digest[:]) {
			t.Errorf("upload MD5 = %q", r.Header.Get("Content-MD5"))
		}
		if r.Header.Get("x-amz-meta-mixed") != "value" || r.Header.Get("x-amz-checksum-crc32") != "" {
			t.Errorf("headers = %v", r.Header)
		}
		if _, ok := r.Header["X-Amz-Meta-Absent"]; ok {
			t.Error("nil metadata was serialized")
		}
		if attempts.Add(1) < 4 {
			w.WriteHeader(500)
			io.WriteString(w, "<Error><Code>InternalError</Code></Error>")
			return
		}
		w.Header().Set("ETag", "etag")
		w.Header().Set("Date", "Fri, 11 Sep 2026 00:00:00 GMT")
	}, nil)
	result, err := backend.PutBlob(&PutBlobInput{Key: "key", Body: bytes.NewReader([]byte("payload")), Metadata: map[string]*string{"MiXeD": aws.String("value"), "absent": nil}})
	if err != nil || attempts.Load() != 4 {
		t.Fatalf("attempts=%d error=%v", attempts.Load(), err)
	}
	if result.LastModified == nil || aws.ToString(result.ETag) != "etag" {
		t.Fatalf("result = %+v", result)
	}
}

func TestS3CompatibilityDeleteMD5AndFallback(t *testing.T) {
	var attempts atomic.Int32
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			attempts.Add(1)
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS access:") {
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(404)
			return
		}
		body, _ := io.ReadAll(r.Body)
		digest := md5.Sum(body)
		if r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(digest[:]) {
			t.Errorf("MD5 = %q", r.Header.Get("Content-MD5"))
		}
		if r.Header.Get("x-amz-checksum-crc32") != "" {
			t.Error("unexpected CRC32")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS access:") {
			t.Error("missing v2 signature")
		}
		io.WriteString(w, "<DeleteResult/>")
	}, nil)
	if err := backend.Init("missing"); err != nil {
		t.Fatal(err)
	}
	if !backend.v2Signer || attempts.Load() != 2 {
		t.Fatalf("fallback=%v attempts=%d", backend.v2Signer, attempts.Load())
	}
	if _, err := backend.DeleteBlobs(&DeleteBlobsInput{Items: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
}

func TestS3CompatibilitySSERequiresTLS(t *testing.T) {
	var calls atomic.Int32
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}, nil)
	backend.config.SseC = "01234567890123456789012345678901"
	for _, operation := range []func() error{
		func() error {
			_, err := backend.HeadBlob(&HeadBlobInput{Key: "key"})
			return err
		},
		func() error {
			_, err := backend.PutBlob(&PutBlobInput{Key: "key", Body: strings.NewReader("payload")})
			return err
		},
		func() error {
			size := uint64(3)
			_, err := backend.CopyBlob(&CopyBlobInput{Source: "source", Destination: "destination", Size: &size, ETag: aws.String("etag")})
			return err
		},
	} {
		if err := operation(); err == nil || !strings.Contains(err.Error(), "cannot send SSE keys over HTTP.") {
			t.Fatalf("error = %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("sent %d unencrypted requests", calls.Load())
	}
}

func TestS3CompatibilityAnonymousAndErrors(t *testing.T) {
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("anonymous request was signed")
		}
		w.WriteHeader(403)
	}, func(c *S3Config) { c.Credentials = aws.AnonymousCredentials{} })
	if _, err := backend.HeadBlob(&HeadBlobInput{Key: "key"}); err != syscall.EACCES {
		t.Fatalf("error = %v", err)
	}
}

func TestGCSCompatibilityResumable(t *testing.T) {
	var starts, parts, retries atomic.Int32
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			starts.Add(1)
			if r.URL.RawQuery != "" || r.Header.Get("x-goog-resumable") != "start" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS access:") {
				t.Errorf("start URL=%s headers=%v", r.URL, r.Header)
			}
			w.Header().Set("Location", "http://"+r.Host+"/resumable?upload_id=token")
			w.WriteHeader(201)
			return
		}
		if r.Header.Get("Content-Range") == "bytes 0-262143/*" && retries.Add(1) == 1 {
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(500)
			io.WriteString(w, "<Error><Code>InternalError</Code></Error>")
			return
		}
		part := parts.Add(1)
		if r.URL.Path != "/resumable" || r.URL.Query().Get("upload_id") != "token" || r.Header.Get("Authorization") != "" {
			t.Errorf("part URL=%s headers=%v", r.URL, r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if part == 1 {
			if len(body) != 256*1024 || r.Header.Get("Content-Range") != "bytes 0-262143/*" {
				t.Errorf("first part len=%d range=%s", len(body), r.Header.Get("Content-Range"))
			}
			w.WriteHeader(308)
		} else {
			if string(body) != "last" || r.Header.Get("Content-Range") != "bytes 262144-262147/262148" {
				t.Errorf("last part body=%q range=%s", body, r.Header.Get("Content-Range"))
			}
			w.Header().Set("ETag", "final")
		}
	}, nil)
	gcs := &GCS3{S3Backend: backend}
	backend.gcs = true
	commit, err := gcs.MultipartBlobBegin(&MultipartBlobBeginInput{Key: "key", ContentType: aws.String("text/plain")})
	if err != nil {
		t.Fatal(err)
	}
	for i, body := range [][]byte{make([]byte, 256*1024), []byte("last")} {
		_, err = gcs.MultipartBlobAdd(&MultipartBlobAddInput{Commit: commit, PartNumber: uint32(i + 1), Body: bytes.NewReader(body), Size: uint64(len(body))})
		if err != nil {
			t.Fatal(err)
		}
	}
	result, err := gcs.MultipartBlobCommit(commit)
	if err != nil || result == nil || aws.ToString(result.ETag) != "final" || starts.Load() != 1 || parts.Load() != 2 {
		t.Fatalf("result=%+v error=%v starts=%d parts=%d", result, err, starts.Load(), parts.Load())
	}
}
