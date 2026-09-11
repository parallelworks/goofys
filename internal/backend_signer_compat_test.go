package internal

import (
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestS3CompatibilityV2Signatures(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, bucket, signature string
		pathStyle                         bool
	}{
		{"path", "https://s3.example/bucket/a%20b%2Bc?uploadId=a%2Bb%2F%3D&partNumber=2&ignored=value", "bucket", "UpDBNEoGs635XNIqfjv9JDFrA00=", true},
		{"virtual", "https://dotted.bucket.s3.example/a%20b%2Bc?uploadId=a%2Bb%2F%3D&partNumber=2", "dotted.bucket", "erwfWpTSRZUfBOPgWwSdoBzny5w=", false},
		{"escaped", "https://s3.example/bucket/a%252Fb", "bucket", "hpO3z8swEuHkgAOCLtzSEgBo/pI=", true},
		{"pathFallback", "https://s3.example/bucket/a%252Fb", "bucket", "hpO3z8swEuHkgAOCLtzSEgBo/pI=", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), "PUT", test.endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-MD5", "md5")
			req.Header.Set("Content-Type", "text/plain")
			req.Header.Set("Authorization", "previous signature")
			credentials := aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret", SessionToken: "token"}
			for range 2 {
				if err := SignV2(req, credentials, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC), test.pathStyle, test.bucket); err != nil {
					t.Fatal(err)
				}
				if got := req.Header.Get("Authorization"); got != "AWS access:"+test.signature {
					t.Fatalf("signature = %q", got)
				}
			}
		})
	}
}
