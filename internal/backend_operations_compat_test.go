package internal

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	. "github.com/kahing/goofys/api/common"
)

func TestS3CompatibilityListVersions(t *testing.T) {
	for _, isAWS := range []bool{false, true} {
		t.Run(map[bool]string{false: "custom", true: "aws"}[isAWS], func(t *testing.T) {
			backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("prefix") != "dir/" || q.Get("delimiter") != "/" || q.Get("max-keys") != "17" {
					t.Errorf("query = %v", q)
				}
				if isAWS {
					if q.Get("list-type") != "2" || q.Get("continuation-token") != "next" || q.Get("start-after") != "after" {
						t.Errorf("v2 query = %v", q)
					}
				} else if q.Get("list-type") != "" || q.Get("marker") != "after" {
					t.Errorf("v1 query = %v", q)
				}
				io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextMarker>marker</NextMarker><NextContinuationToken>token</NextContinuationToken><Contents><Key>dir/key</Key><Size>3</Size><StorageClass>STANDARD</StorageClass></Contents><CommonPrefixes><Prefix>dir/sub/</Prefix></CommonPrefixes></ListBucketResult>`)
			}, nil)
			backend.aws = isAWS
			maxKeys := uint32(17)
			got, err := backend.ListBlobs(&ListBlobsInput{Prefix: aws.String("dir/"), Delimiter: aws.String("/"), MaxKeys: &maxKeys, StartAfter: aws.String("after"), ContinuationToken: aws.String("next")})
			if err != nil {
				t.Fatal(err)
			}
			wantToken := "marker"
			if isAWS {
				wantToken = "token"
			}
			if !got.IsTruncated || aws.ToString(got.NextContinuationToken) != wantToken || len(got.Items) != 1 || got.Items[0].Size != 3 || len(got.Prefixes) != 1 {
				t.Fatalf("list = %+v", got)
			}
		})
	}
}

func TestS3CompatibilityMultipart(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	var calls atomic.Int32
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == "POST" && r.Header.Get("x-amz-request-payer") != "requester" {
			t.Error("missing request payer")
		}
		w.Header().Set("x-amz-request-id", "request")
		w.Header().Set("x-amz-id-2", "host")
		switch {
		case r.URL.Query().Has("uploads"):
			if r.Header.Get("x-amz-server-side-encryption-customer-key") != key || r.Header.Get("x-amz-acl") != "private" {
				t.Errorf("begin headers = %v", r.Header)
			}
			io.WriteString(w, `<InitiateMultipartUploadResult><UploadId>upload+id/=</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == "PUT":
			if r.URL.Query().Get("uploadId") != "upload+id/=" || r.URL.Query().Get("partNumber") != "1" || r.Header.Get("x-amz-server-side-encryption-customer-key") != key {
				t.Errorf("part URL=%s headers=%v", r.URL, r.Header)
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != "part" {
				t.Errorf("part body = %q", body)
			}
			w.Header().Set("ETag", "\"part-etag\"")
		case r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte("part-etag")) || !bytes.Contains(body, []byte("<PartNumber>1</PartNumber>")) {
				t.Errorf("complete body = %q", body)
			}
			io.WriteString(w, `<CompleteMultipartUploadResult><ETag>"final"</ETag></CompleteMultipartUploadResult>`)
		case r.Method == "DELETE":
			w.WriteHeader(204)
		}
	}, func(c *S3Config) { c.SseC = key; c.RequesterPays = true; c.ACL = "private" })
	commit, err := backend.MultipartBlobBegin(&MultipartBlobBeginInput{Key: "key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.MultipartBlobAdd(&MultipartBlobAddInput{Commit: commit, PartNumber: 1, Size: 4, Body: strings.NewReader("part")}); err != nil {
		t.Fatal(err)
	}
	result, err := backend.MultipartBlobCommit(commit)
	if err != nil || result == nil || aws.ToString(result.ETag) != `"final"` || result.RequestId != "request: host" || result.LastModified == nil {
		t.Fatalf("complete=%+v error=%v", result, err)
	}
	if _, err := backend.MultipartBlobAbort(commit); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestS3CompatibilityCreateBucketRegion(t *testing.T) {
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		t.Run(region, func(t *testing.T) {
			backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if region == "us-east-1" && len(body) != 0 {
					t.Errorf("unexpected create body = %q", body)
				}
				if region != "us-east-1" && !strings.Contains(string(body), "<LocationConstraint>"+region+"</LocationConstraint>") {
					t.Errorf("create body = %q", body)
				}
			}, func(c *S3Config) { c.Region = region })
			if _, err := backend.MakeBucket(&MakeBucketInput{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestS3CompatibilityBucketTaggingMD5(t *testing.T) {
	backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		digest := md5.Sum(body)
		if r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(digest[:]) || r.Header.Get("x-amz-checksum-crc32") != "" {
			t.Errorf("headers = %v", r.Header)
		}
		w.WriteHeader(204)
	}, nil)
	_, err := backend.PutBucketTagging(t.Context(), &s3.PutBucketTaggingInput{Bucket: aws.String("bucket"), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("Owner"), Value: aws.String("owner")}}}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestS3CompatibilityBucketDetection(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "region", true: "anonymous"}[anonymous], func(t *testing.T) {
			var calls atomic.Int32
			backend := compatBackend(t, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					if r.URL.Path != "/bucket" || r.Header.Get("Authorization") != "" {
						t.Errorf("discovery URL=%s headers=%v", r.URL, r.Header)
					}
					w.Header().Set("Server", "AmazonS3")
					w.Header().Set("x-amz-bucket-region", "us-west-2")
					if !anonymous {
						w.WriteHeader(403)
					}
					return
				}
				if anonymous && r.Header.Get("Authorization") != "" {
					t.Error("anonymous request was signed")
				}
				if !anonymous && !strings.Contains(r.Header.Get("Authorization"), "/us-west-2/s3/aws4_request") {
					t.Errorf("authorization = %q", r.Header.Get("Authorization"))
				}
				w.WriteHeader(404)
			}, func(c *S3Config) { c.RegionSet = false })
			if err := backend.Init("missing"); err != nil {
				t.Fatal(err)
			}
			if backend.awsConfig.Region != "us-west-2" || !backend.aws || backend.v2Signer {
				t.Fatalf("region=%s aws=%v v2=%v", backend.awsConfig.Region, backend.aws, backend.v2Signer)
			}
		})
	}
}
