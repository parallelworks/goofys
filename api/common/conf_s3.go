// Copyright 2019 Databricks
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

package common

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/logging"
)

type S3Config struct {
	Profile         string
	AccessKey       string
	SecretKey       string
	RoleArn         string
	RoleExternalId  string
	RoleSessionName string
	StsEndpoint     string

	RequesterPays bool
	Region        string
	RegionSet     bool

	StorageClass string

	UseSSE     bool
	UseKMS     bool
	KMSKeyID   string
	SseC       string
	SseCDigest string
	ACL        string

	Subdomain bool

	Credentials aws.CredentialsProvider
	Session     *aws.Config

	BucketOwner string
}

func (c *S3Config) Init() *S3Config {
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.StorageClass == "" {
		c.StorageClass = "STANDARD"
	}
	return c
}

func (c *S3Config) ToAwsConfig(flags *FlagStorage) (*aws.Config, error) {
	ctx := context.Background()
	httpClient := &http.Client{
		Transport: &defaultHTTPTransport,
		Timeout:   flags.HTTPTimeout,
	}
	log := GetLogger("s3")
	sdkLogger := logging.LoggerFunc(func(_ logging.Classification, format string, args ...interface{}) {
		log.Debugf(format, args...)
	})
	var logMode aws.ClientLogMode
	if flags.DebugS3 {
		logMode = aws.LogRequest | aws.LogResponse | aws.LogRetries
	}
	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(c.Region),
		config.WithHTTPClient(httpClient),
		config.WithLogger(sdkLogger),
		config.WithClientLogMode(logMode),
	}
	if c.Credentials == nil && c.AccessKey != "" {
		c.Credentials = credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, "")
	}
	if c.Session == nil {
		options := sharedConfigLoadOptions(c.Profile, loadOptions)
		if c.Credentials != nil {
			options = append(options, config.WithCredentialsProvider(c.Credentials))
		}
		loaded, err := config.LoadDefaultConfig(ctx, options...)
		if err != nil {
			return nil, err
		}
		if c.Credentials == nil {
			loaded.Credentials = &sharedFileProvider{profile: c.Profile, loadOptions: loadOptions}
		}
		c.Session = &loaded
	} else if c.Credentials == nil && c.Profile != "" {
		c.Credentials = &sharedFileProvider{profile: c.Profile, loadOptions: loadOptions}
	}

	awsConfig := c.Session.Copy()
	awsConfig.Region = c.Region
	awsConfig.HTTPClient = httpClient
	awsConfig.Logger = sdkLogger
	awsConfig.ClientLogMode = logMode
	if awsConfig.Retryer == nil {
		awsConfig.Retryer = func() aws.Retryer {
			return retry.NewStandard(func(options *retry.StandardOptions) {
				options.MaxAttempts = 4
				options.RateLimiter = ratelimit.None
			})
		}
	}
	if c.Credentials != nil {
		awsConfig.Credentials = c.Credentials
	}

	if c.RoleArn != "" {
		stsClient := sts.NewFromConfig(awsConfig, func(options *sts.Options) {
			if c.StsEndpoint != "" {
				options.BaseEndpoint = aws.String(c.StsEndpoint)
			}
		})
		awsConfig.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, c.RoleArn,
			func(options *stscreds.AssumeRoleOptions) {
				if c.RoleExternalId != "" {
					options.ExternalID = aws.String(c.RoleExternalId)
				}
				options.RoleSessionName = c.RoleSessionName
			}))
	}

	if c.SseC != "" {
		key, err := base64.StdEncoding.DecodeString(c.SseC)
		if err != nil {
			return nil, fmt.Errorf("sse-c is not base64-encoded: %v", err)
		}

		c.SseC = string(key)
		m := md5.Sum(key)
		c.SseCDigest = base64.StdEncoding.EncodeToString(m[:])
	}

	return &awsConfig, nil
}
