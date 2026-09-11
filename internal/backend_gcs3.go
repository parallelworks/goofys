// Copyright 2019 Ka-Hing Cheung
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package internal

import (
	. "github.com/kahing/goofys/api/common"

	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/jacobsa/fuse"
)

// GCS variant of S3
type GCS3 struct {
	*S3Backend

	resumableMu     sync.Mutex
	resumableBase   *s3.Client
	resumableStart  *s3.Client
	resumableUpload *s3.Client
}

func (s *GCS3) resumableClients() (start, upload *s3.Client) {
	s.resumableMu.Lock()
	defer s.resumableMu.Unlock()
	if s.resumableBase != s.Client {
		options := s.Client.Options()
		options.AuthSchemes = nil
		s.resumableStart = s3.New(options, V2Signer(s.bucket))
		options = s.Client.Options()
		options.Credentials = aws.AnonymousCredentials{}
		s.resumableUpload = s3.New(options)
		s.resumableBase = s.Client
	}
	return s.resumableStart, s.resumableUpload
}

type GCS3MultipartBlobCommitInput struct {
	Size uint64
	ETag *string
	Prev *MultipartBlobAddInput
}

func NewGCS3(bucket string, flags *FlagStorage, config *S3Config) (*GCS3, error) {
	s3Backend, err := NewS3(bucket, flags, config)
	if err != nil {
		return nil, err
	}
	s3Backend.Capabilities().Name = "gcs3"
	s := &GCS3{S3Backend: s3Backend}
	s.S3Backend.gcs = true
	s.S3Backend.cap.NoParallelMultipart = true
	return s, nil
}

func (s *GCS3) Delegate() interface{} {
	return s
}

func (s *GCS3) DeleteBlobs(param *DeleteBlobsInput) (*DeleteBlobsOutput, error) {
	// GCS does not have multi-delete
	var wg sync.WaitGroup
	var overallErr error

	for _, key := range param.Items {
		wg.Add(1)
		go func(key string) {
			_, err := s.DeleteBlob(&DeleteBlobInput{
				Key: key,
			})
			if err != nil && err != fuse.ENOENT {
				overallErr = err
			}
			wg.Done()
		}(key)
	}
	wg.Wait()
	if overallErr != nil {
		return nil, mapAwsError(overallErr)
	}

	return &DeleteBlobsOutput{}, nil
}

func gcsRequest(update func(*smithyhttp.Request) error, response **http.Response, upload bool) func(*s3.Options) {
	return func(o *s3.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			if err := stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("GCSResumableRequest", func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
				if err := update(in.Request.(*smithyhttp.Request)); err != nil {
					return middleware.FinalizeOutput{}, middleware.Metadata{}, err
				}
				return next.HandleFinalize(ctx, in)
			}), "Signing", middleware.Before); err != nil {
				return err
			}
			return stack.Deserialize.Add(middleware.DeserializeMiddlewareFunc("GCSResumableResponse", func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
				out, metadata, err := next.HandleDeserialize(ctx, in)
				if resp, ok := out.RawResponse.(*smithyhttp.Response); ok {
					*response = resp.Response
					if upload && resp.StatusCode == 308 {
						out.Result = &s3.PutObjectOutput{ETag: aws.String(resp.Header.Get("ETag"))}
						err = nil
					} else if !upload && resp.StatusCode >= 200 && resp.StatusCode < 300 {
						out.Result = &s3.CreateMultipartUploadOutput{}
						err = nil
					}
				}
				return out, metadata, err
			}), middleware.Before)
		})
	}
}

func (s *GCS3) MultipartBlobBegin(param *MultipartBlobBeginInput) (*MultipartBlobCommitInput, error) {
	mpu := s3.CreateMultipartUploadInput{
		Bucket:       &s.bucket,
		Key:          &param.Key,
		StorageClass: types.StorageClass(s.config.StorageClass),
		ContentType:  param.ContentType,
	}

	if s.config.UseSSE {
		mpu.ServerSideEncryption = s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			mpu.SSEKMSKeyId = &s.config.KMSKeyID
		}
	}

	if s.config.ACL != "" {
		mpu.ACL = types.ObjectCannedACL(s.config.ACL)
	}

	var response *http.Response
	client, _ := s.resumableClients()
	_, err := client.CreateMultipartUpload(context.TODO(), &mpu, gcsRequest(func(req *smithyhttp.Request) error {
		req.URL.RawQuery = ""
		req.Header.Set("x-goog-resumable", "start")
		return nil
	}, &response, false))
	if err != nil {
		s3Log.Errorf("CreateMultipartUpload %v = %v", param.Key, err)
		return nil, mapAwsError(err)
	}

	location := response.Header.Get("Location")
	_, err = url.Parse(location)
	if err != nil {
		s3Log.Errorf("CreateMultipartUpload %v %v = %v", param.Key, location, err)
		return nil, mapAwsError(err)
	}

	return &MultipartBlobCommitInput{
		Key:         &param.Key,
		Metadata:    param.Metadata,
		UploadId:    &location,
		Parts:       make([]*string, 10000), // at most 10K parts
		backendData: &GCS3MultipartBlobCommitInput{},
	}, nil
}

func (s *GCS3) uploadPart(param *MultipartBlobAddInput, totalSize uint64, last bool) (etag *string, err error) {
	atomic.AddUint32(&param.Commit.NumParts, 1)

	if closer, ok := param.Body.(io.Closer); ok {
		defer closer.Close()
	}

	// the mpuId serves as authentication token so
	// technically we don't need to sign this anymore and
	// can just use a plain HTTP request, but going
	// through aws-sdk-go anyway to get retry handling
	params := &s3.PutObjectInput{
		Bucket: &s.bucket,
		Key:    param.Commit.Key,
		Body:   param.Body,
	}

	s3Log.Debug(params)

	location, err := url.Parse(*param.Commit.UploadId)
	if err != nil {
		return nil, err
	}

	start := totalSize - param.Size
	end := totalSize - 1
	var size string
	if last {
		size = strconv.FormatUint(totalSize, 10)
	} else {
		size = "*"
	}

	contentRange := fmt.Sprintf("bytes %v-%v/%v", start, end, size)

	params.ContentLength = aws.Int64(int64(param.Size))
	var response *http.Response
	_, client := s.resumableClients()
	resp, err := client.PutObject(context.TODO(), params, gcsRequest(func(req *smithyhttp.Request) error {
		req.URL = location
		req.Header.Set("Content-Range", contentRange)
		return nil
	}, &response, true))
	if err != nil {
		return nil, mapAwsError(err)
	}

	etag = resp.ETag

	return
}

func (s *GCS3) MultipartBlobAdd(param *MultipartBlobAddInput) (*MultipartBlobAddOutput, error) {
	var commitData *GCS3MultipartBlobCommitInput
	var ok bool
	if commitData, ok = param.Commit.backendData.(*GCS3MultipartBlobCommitInput); !ok {
		panic("Incorrect commit data type")
	}

	if commitData.Prev != nil {
		if commitData.Prev.Size == 0 || commitData.Prev.Size%(256*1024) != 0 {
			s3Log.Errorf("size of each block must be multiple of 256KB: %v", param.Size)
			return nil, fuse.EINVAL
		}

		_, err := s.uploadPart(commitData.Prev, commitData.Size, false)
		if err != nil {
			return nil, err
		}
	}
	commitData.Size += param.Size

	copy := *param
	commitData.Prev = &copy
	param.Body = nil

	return &MultipartBlobAddOutput{}, nil
}

func (s *GCS3) MultipartBlobCommit(param *MultipartBlobCommitInput) (*MultipartBlobCommitOutput, error) {
	var commitData *GCS3MultipartBlobCommitInput
	var ok bool
	if commitData, ok = param.backendData.(*GCS3MultipartBlobCommitInput); !ok {
		panic("Incorrect commit data type")
	}

	if commitData.Prev == nil {
		panic("commit should include last part")
	}

	etag, err := s.uploadPart(commitData.Prev, commitData.Size, true)
	if err != nil {
		return nil, err
	}

	return &MultipartBlobCommitOutput{
		ETag: etag,
	}, nil
}
