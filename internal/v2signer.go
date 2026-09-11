// Copyright 2015 - 2017 Ka-Hing Cheung
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
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/encoding/httpbinding"
	"github.com/aws/smithy-go/logging"
)

var (
	errInvalidMethod = errors.New("v2 signer does not handle HTTP POST")
)

const (
	signatureVersion = "2"
	signatureMethod  = "HmacSHA1"
	timeFormat       = "Mon, 02 Jan 2006 15:04:05 +0000"
)

var subresources = []string{
	"acl",
	"delete",
	"lifecycle",
	"location",
	"logging",
	"notification",
	"partNumber",
	"policy",
	"requestPayment",
	"torrent",
	"uploadId",
	"uploads",
	"versionId",
	"versioning",
	"versions",
	"website",
}

type signer struct {
	// Values that must be populated from the request
	Request     *http.Request
	Time        time.Time
	Credentials aws.Credentials
	Debug       aws.ClientLogMode
	Logger      logging.Logger
	pathStyle   bool
	bucket      string

	Query        url.Values
	stringToSign string
	signature    string
}

func SignV2(req *http.Request, credentials aws.Credentials, signingTime time.Time, pathStyle bool, bucket string) error {
	v2 := signer{
		Request:     req,
		Time:        signingTime,
		Credentials: credentials,
		pathStyle:   pathStyle,
		bucket:      bucket,
	}
	return v2.Sign()
}

type v2HTTPsigner struct {
	bucket    string
	pathStyle bool
}

func (s v2HTTPsigner) SignHTTP(ctx context.Context, credentials aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time, optFns ...func(*v4.SignerOptions)) error {
	return SignV2(req, credentials, signingTime, s.pathStyle, s.bucket)
}

func V2Signer(bucket string) func(*s3.Options) {
	return func(o *s3.Options) {
		o.HTTPSignerV4 = v2HTTPsigner{bucket: bucket, pathStyle: o.UsePathStyle}
	}
}

func (v2 *signer) Sign() error {
	credValue := v2.Credentials

	v2.Query = v2.Request.URL.Query()

	contentMD5 := v2.Request.Header.Get("Content-MD5")
	contentType := v2.Request.Header.Get("Content-Type")
	date := v2.Time.UTC().Format(timeFormat)
	v2.Request.Header.Set("x-amz-date", date)

	if credValue.SessionToken != "" {
		v2.Request.Header.Set("x-amz-security-token", credValue.SessionToken)
	}

	// in case this is a retry, ensure no signature present
	v2.Request.Header.Del("Authorization")

	method := v2.Request.Method

	uri := v2.Request.URL.Opaque
	if uri != "" {
		if questionMark := strings.Index(uri, "?"); questionMark != -1 {
			uri = uri[0:questionMark]
		}
		uri = "/" + strings.Join(strings.Split(uri, "/")[3:], "/")
	} else {
		uri = v2.Request.URL.Path
	}
	path := httpbinding.EscapePath(uri, false)
	if !v2.pathStyle && strings.HasPrefix(v2.Request.URL.Host, v2.bucket+".") {
		path = "/" + v2.bucket + path
	}
	if path == "" {
		path = "/"
	}

	// build URL-encoded query keys and values
	queryKeysAndValues := []string{}
	for _, key := range subresources {
		if _, ok := v2.Query[key]; ok {
			k := strings.Replace(url.QueryEscape(key), "+", "%20", -1)
			v := strings.Replace(url.QueryEscape(v2.Query.Get(key)), "+", "%20", -1)
			if v != "" {
				v = "=" + v
			}
			queryKeysAndValues = append(queryKeysAndValues, k+v)
		}
	}

	// join into one query string
	query := strings.Join(queryKeysAndValues, "&")

	if query != "" {
		path += "?" + query
	}

	tmp := []string{
		method,
		contentMD5,
		contentType,
		"",
	}

	var headers []string
	for k := range v2.Request.Header {
		k = strings.ToLower(k)
		if strings.HasPrefix(k, "x-amz-") {
			headers = append(headers, k)
		}
	}
	sort.Strings(headers)

	for _, k := range headers {
		v := strings.Join(v2.Request.Header[http.CanonicalHeaderKey(k)], ",")
		tmp = append(tmp, k+":"+v)
	}

	tmp = append(tmp, path)

	// build the canonical string for the V2 signature
	v2.stringToSign = strings.Join(tmp, "\n")

	hash := hmac.New(sha1.New, []byte(credValue.SecretAccessKey))
	hash.Write([]byte(v2.stringToSign))
	v2.signature = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	v2.Request.Header.Set("Authorization",
		"AWS "+credValue.AccessKeyID+":"+v2.signature)

	if v2.Debug.IsSigning() && v2.Logger != nil {
		v2.logSigningInfo()
	}

	return nil
}

const logSignInfoMsg = `DEBUG: Request Signature:
---[ STRING TO SIGN ]--------------------------------
%s
---[ SIGNATURE ]-------------------------------------
%s
-----------------------------------------------------`

func (v2 *signer) logSigningInfo() {
	msg := fmt.Sprintf(logSignInfoMsg, v2.stringToSign, v2.Request.Header.Get("Authorization"))
	v2.Logger.Logf(logging.Debug, "%s", msg)
}
