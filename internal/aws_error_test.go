package internal

import (
	"errors"
	"fmt"
	"net/http"
	"syscall"
	"testing"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestMapAwsError(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   string
		status int
		want   error
	}{
		{"missing bucket", "NoSuchBucket", 404, syscall.ENXIO},
		{"owned bucket", "BucketAlreadyOwnedByYou", 409, syscall.EEXIST},
		{"invalid request", "InvalidArgument", 400, syscall.EINVAL},
		{"unauthorized", "Unauthorized", 401, syscall.EACCES},
		{"access denied", "AccessDenied", 403, syscall.EACCES},
		{"missing object", "NoSuchKey", 404, syscall.ENOENT},
		{"unsupported", "MethodNotAllowed", 405, syscall.ENOTSUP},
		{"conflict", "Conflict", 409, syscall.EINTR},
		{"throttled", "TooManyRequests", 429, syscall.EAGAIN},
		{"server error", "InternalError", 500, syscall.EAGAIN},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := &smithy.OperationError{
				ServiceID:     "S3",
				OperationName: "HeadObject",
				Err: &smithyhttp.ResponseError{
					Response: &smithyhttp.Response{Response: &http.Response{StatusCode: test.status}},
					Err:      &smithy.GenericAPIError{Code: test.code, Message: test.name},
				},
			}
			if got := mapAwsError(fmt.Errorf("wrapped: %w", err)); !errors.Is(got, test.want) {
				t.Fatalf("mapAwsError() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMapAwsErrorPreservesUnknownErrors(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("transport failed"),
		&smithy.GenericAPIError{Code: "PermanentRedirect"},
		&smithy.GenericAPIError{Code: "UnknownError"},
		&smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 503}},
			Err:      errors.New("unavailable"),
		},
	} {
		if got := mapAwsError(err); got != err {
			t.Fatalf("mapAwsError(%v) = %v", err, got)
		}
	}
}
