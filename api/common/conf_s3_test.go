package common

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestToAwsConfigCredentialPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		config     S3Config
		envProfile string
		want       string
	}{
		{name: "explicit provider", config: S3Config{Credentials: credentials.NewStaticCredentialsProvider("CUSTOM", "custom-secret", ""), AccessKey: "STATIC", SecretKey: "static-secret", Profile: "bucket"}, want: "CUSTOM"},
		{name: "static keys", config: S3Config{AccessKey: "STATIC", SecretKey: "static-secret", Profile: "bucket"}, want: "STATIC"},
		{name: "explicit profile", config: S3Config{Profile: "bucket"}, want: "PROFILE"},
		{name: "environment", want: "ENV"},
		{name: "environment profile with environment keys", envProfile: "bucket", want: "ENV"},
		{name: "supplied session", config: S3Config{Session: &aws.Config{Credentials: credentials.NewStaticCredentialsProvider("SESSION", "session-secret", "")}}, want: "SESSION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := sharedCredentialsFile(t)
			writeSharedCredentials(t, path, "bucket", "PROFILE", "profile-secret", "")
			t.Setenv("AWS_ACCESS_KEY_ID", "ENV")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
			t.Setenv("AWS_PROFILE", tc.envProfile)
			cfg, err := tc.config.Init().ToAwsConfig(&FlagStorage{})
			if err != nil {
				t.Fatal(err)
			}
			value, err := cfg.Credentials.Retrieve(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if value.AccessKeyID != tc.want {
				t.Fatalf("credential source = %q, want %q", value.AccessKeyID, tc.want)
			}
		})
	}
}

func TestToAwsConfigProfilesDoNotShareSession(t *testing.T) {
	path := sharedCredentialsFile(t)
	if err := os.WriteFile(path, []byte("[first]\naws_access_key_id=FIRST\naws_secret_access_key=first-secret\n[second]\naws_access_key_id=SECOND\naws_secret_access_key=second-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first := (&S3Config{Profile: "first"}).Init()
	second := (&S3Config{Profile: "second"}).Init()
	for _, c := range []*S3Config{first, second} {
		cfg, err := c.ToAwsConfig(&FlagStorage{})
		if err != nil {
			t.Fatal(err)
		}
		value, err := cfg.Credentials.Retrieve(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if value.AccessKeyID != strings.ToUpper(c.Profile) {
			t.Fatalf("profile %q resolved %q", c.Profile, value.AccessKeyID)
		}
	}
	if first.Session == second.Session {
		t.Fatal("independent profiles must not share session configuration")
	}
}

func TestToAwsConfigDefaultCredentialsRotate(t *testing.T) {
	for _, profile := range []string{"", "bucket"} {
		t.Run("AWS_PROFILE="+profile, func(t *testing.T) {
			path := sharedCredentialsFile(t)
			t.Setenv("AWS_PROFILE", profile)
			if profile == "" {
				profile = "default"
			}
			writeSharedCredentials(t, path, profile, "OLD", "old-secret", "old-token")
			cfg, err := (&S3Config{}).Init().ToAwsConfig(&FlagStorage{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cfg.Credentials.Retrieve(t.Context()); err != nil {
				t.Fatal(err)
			}
			rotateSharedCredentials(t, path, profile, "NEW", "new-secret", "new-token")
			provider := cfg.Credentials.(*sharedFileProvider)
			provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)
			var wg sync.WaitGroup
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					value, err := cfg.Credentials.Retrieve(t.Context())
					if err != nil {
						t.Error(err)
						return
					}
					if value.AccessKeyID != "NEW" || value.SessionToken != "new-token" {
						t.Error("default credentials did not rotate")
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestS3ClientCredentialsFollowRotation(t *testing.T) {
	for _, profile := range []string{"", "bucket"} {
		t.Run("profile="+profile, func(t *testing.T) {
			path := sharedCredentialsFile(t)
			fileProfile := profile
			if fileProfile == "" {
				fileProfile = "default"
			}
			writeSharedCredentials(t, path, fileProfile, "OLD", "old-secret", "old-token")
			authorizations := make(chan string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authorizations <- r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			cfg, err := (&S3Config{Profile: profile}).Init().ToAwsConfig(&FlagStorage{HTTPTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			client := s3.NewFromConfig(*cfg, func(options *s3.Options) { options.BaseEndpoint = aws.String(server.URL); options.UsePathStyle = true })
			for _, key := range []string{"OLD", "NEW"} {
				if _, err := client.HeadBucket(t.Context(), &s3.HeadBucketInput{Bucket: aws.String("bucket")}); err != nil {
					t.Fatal(err)
				}
				if auth := <-authorizations; !strings.Contains(auth, "Credential="+key+"/") {
					t.Fatalf("request authorization did not use %s: %s", key, auth)
				}
				if key == "OLD" {
					rotateSharedCredentials(t, path, fileProfile, "NEW", "new-secret", "new-token")
					cfg.Credentials.(*sharedFileProvider).checkedAt = time.Now().Add(-sharedCredentialsStatInterval)
				}
			}
		})
	}
}

func TestToAwsConfigAssumeRole(t *testing.T) {
	sharedCredentialsFile(t)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		for key, want := range map[string]string{"Action": "AssumeRole", "RoleArn": "arn:aws:iam::123456789012:role/bucket", "ExternalId": "external", "RoleSessionName": "mount"} {
			if got := r.Form.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=SOURCE/") {
			t.Errorf("STS used incorrect source: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASSUMED</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>id:mount</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/bucket/mount</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer server.Close()
	cfg, err := (&S3Config{AccessKey: "SOURCE", SecretKey: "source-secret", RoleArn: "arn:aws:iam::123456789012:role/bucket", RoleExternalId: "external", RoleSessionName: "mount", StsEndpoint: server.URL}).Init().ToAwsConfig(&FlagStorage{Endpoint: "http://must-not-receive-sts.invalid", HTTPTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		value, err := cfg.Credentials.Retrieve(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if value.AccessKeyID != "ASSUMED" || value.SessionToken != "assumed-token" {
			t.Fatal("role credentials were not returned")
		}
	}
	if calls != 1 {
		t.Fatalf("STS requests = %d, want one cached assumption", calls)
	}
}

func TestToAwsConfigNamedRoleProfile(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "source", "SOURCE", "source-secret", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("ExternalId") != "profile-external" || r.Form.Get("RoleSessionName") != "profile-session" {
			t.Error("named role options were not preserved")
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=SOURCE/") {
			t.Error("explicit role profile must override environment credentials")
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>PROFILE-ROLE</AccessKeyId><SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
	}))
	defer server.Close()
	t.Setenv("AWS_ENDPOINT_URL_STS", server.URL)
	contents := "[profile bucket]\nrole_arn=arn:aws:iam::123456789012:role/bucket\nsource_profile=source\nexternal_id=profile-external\nrole_session_name=profile-session\n"
	if err := os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := (&S3Config{Profile: "bucket"}).Init().ToAwsConfig(&FlagStorage{HTTPTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	value, err := cfg.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "PROFILE-ROLE" {
		t.Fatalf("named role profile resolved %q", value.AccessKeyID)
	}
}

func TestToAwsConfigRetryPolicy(t *testing.T) {
	sharedCredentialsFile(t)
	cfg, err := (&S3Config{AccessKey: "KEY", SecretKey: "secret"}).Init().ToAwsConfig(&FlagStorage{})
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Retryer()
	if r.MaxAttempts() != 4 {
		t.Fatalf("max attempts = %d, want 4", r.MaxAttempts())
	}
	for range 200 {
		release, err := r.GetRetryToken(t.Context(), errors.New("retry"))
		if err != nil {
			t.Fatalf("retry quota must not limit requests: %v", err)
		}
		if err := release(errors.New("failed")); err != nil {
			t.Fatal(err)
		}
	}
	custom := retry.NewStandard(func(options *retry.StandardOptions) { options.MaxAttempts = 7 })
	cfg, err = (&S3Config{AccessKey: "KEY", SecretKey: "secret", Session: &aws.Config{Retryer: func() aws.Retryer { return custom }}}).Init().ToAwsConfig(&FlagStorage{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retryer() != custom {
		t.Fatal("custom session retryer was replaced")
	}
}

func TestToAwsConfigHTTPLoggingAndSSEC(t *testing.T) {
	sharedCredentialsFile(t)
	key := "0123456789abcdef0123456789abcdef"
	c := (&S3Config{AccessKey: "KEY", SecretKey: "secret", Region: "us-west-2", SseC: base64.StdEncoding.EncodeToString([]byte(key))}).Init()
	cfg, err := c.ToAwsConfig(&FlagStorage{HTTPTimeout: 17 * time.Second, DebugS3: true})
	if err != nil {
		t.Fatal(err)
	}
	client, ok := cfg.HTTPClient.(*http.Client)
	if !ok || client.Timeout != 17*time.Second || client.Transport != &defaultHTTPTransport {
		t.Fatal("configured HTTP client was not preserved")
	}
	if cfg.Logger == nil || !cfg.ClientLogMode.IsRequest() || !cfg.ClientLogMode.IsResponse() || !cfg.ClientLogMode.IsRetries() {
		t.Fatal("SDK debug logging was not configured")
	}
	if cfg.Region != "us-west-2" {
		t.Fatalf("region = %q", cfg.Region)
	}
	digest := md5.Sum([]byte(key))
	if c.SseC != key || c.SseCDigest != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("SSE-C key or digest changed")
	}
	invalid := (&S3Config{AccessKey: "KEY", SecretKey: "secret", SseC: "not base64"}).Init()
	if _, err := invalid.ToAwsConfig(&FlagStorage{}); err == nil || !strings.Contains(err.Error(), "sse-c is not base64-encoded") {
		t.Fatalf("invalid SSE-C error = %v", err)
	}
}
