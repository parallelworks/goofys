// Copyright 2026 Parallel Works Inc.
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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSharedCredentials(t *testing.T, path, profile, accessKey, secretKey, sessionToken string) {
	t.Helper()
	contents := fmt.Sprintf("[%s]\naws_access_key_id=%s\naws_secret_access_key=%s\naws_session_token=%s\n",
		profile, accessKey, secretKey, sessionToken)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func sharedCredentialsFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", path)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_ROLE_ARN", "")
	return path
}

func rotateSharedCredentials(t *testing.T, path, profile, accessKey, secretKey, sessionToken string) {
	t.Helper()
	writeSharedCredentials(t, path, profile, accessKey, secretKey, sessionToken)
	rotatedAt := time.Now().Add(time.Second)
	if err := os.Chtimes(path, rotatedAt, rotatedAt); err != nil {
		t.Fatal(err)
	}
}

func TestSharedFileCredentialsRereadAfterExpire(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	creds := newSharedFileCredentials("bucket")
	if creds == nil {
		t.Fatal("newSharedFileCredentials() = nil, want credentials")
	}

	value, err := creds.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIAOLD" || value.SessionToken != "token-old" {
		t.Fatalf("initial credentials = %+v, want the original profile", value)
	}

	writeSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	creds.Expire()

	value, err = creds.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIANEW" || value.SecretAccessKey != "secret-new" || value.SessionToken != "token-new" {
		t.Errorf("credentials after expiry = %+v, want the rotated profile", value)
	}
}

func TestSharedFileCredentialsRereadAfterRotation(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	provider := &sharedFileProvider{profile: "bucket"}
	creds := provider

	value, err := creds.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIAOLD" {
		t.Fatalf("initial credentials = %+v, want the original profile", value)
	}

	rotateSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)

	value, err = creds.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIANEW" || value.SecretAccessKey != "secret-new" || value.SessionToken != "token-new" {
		t.Errorf("credentials after rotation = %+v, want the rotated profile", value)
	}
}

func TestSharedFileProviderIsExpired(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	provider := &sharedFileProvider{profile: "bucket"}
	if _, err := provider.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}

	if provider.IsExpired() {
		t.Error("credentials must not expire while the file is unchanged")
	}

	writeSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	if provider.IsExpired() {
		t.Error("the file must not be re-stated within the stat interval")
	}

	rotateSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)

	if !provider.IsExpired() {
		t.Error("a rewritten credentials file must expire the cached credentials")
	}
	if !provider.IsExpired() {
		t.Error("a detected rotation must stay expired until the credentials are reloaded")
	}
}

func TestSharedFileProviderIsExpiredIgnoresPreservedTimestamp(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	provider := &sharedFileProvider{profile: "bucket"}
	if _, err := provider.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}

	writeSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new-and-longer")
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)

	if !provider.IsExpired() {
		t.Error("a rewritten credentials file must expire the cached credentials even with a preserved timestamp")
	}
}

func TestSharedFileProviderMissingFileKeepsCredentials(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	provider := &sharedFileProvider{profile: "bucket"}
	if _, err := provider.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)

	if provider.IsExpired() {
		t.Error("an unreadable credentials file must keep the cached credentials")
	}
}

func TestSharedFileProviderFailedReloadKeepsCredentials(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	provider := &sharedFileProvider{profile: "bucket"}
	if _, err := provider.Retrieve(t.Context()); err != nil {
		t.Fatal(err)
	}

	rotateSharedCredentials(t, path, "other", "AKIANEW", "secret-new", "token-new")
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)

	value, err := provider.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve() = %v, want the previously loaded credentials", err)
	}
	if value.AccessKeyID != "AKIAOLD" {
		t.Errorf("credentials after a failed reload = %+v, want the previously loaded profile", value)
	}
}

func TestSharedFileProviderFailedReloadRecovers(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "OLD", "old-secret", "old-token")
	provider := newSharedFileCredentials("bucket")
	if err := os.WriteFile(path, []byte("[invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)
	value, err := provider.Retrieve(t.Context())
	if err != nil || value.AccessKeyID != "OLD" {
		t.Fatalf("failed reload must preserve old credentials: %v, %q", err, value.AccessKeyID)
	}
	rotateSharedCredentials(t, path, "bucket", "NEW", "new-secret", "new-token")
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)
	value, err = provider.Retrieve(t.Context())
	if err != nil || value.AccessKeyID != "NEW" {
		t.Fatalf("provider did not recover after file became readable: %v, %q", err, value.AccessKeyID)
	}
}

func TestSharedFileProviderRefreshesExpiredCredentials(t *testing.T) {
	for _, profile := range []string{"", "bucket"} {
		t.Run("profile="+profile, func(t *testing.T) {
			path := sharedCredentialsFile(t)
			fileProfile := profile
			if fileProfile == "" {
				fileProfile = "default"
			}
			writeSharedCredentials(t, path, fileProfile, "KEY", "secret", "token")
			cfg, err := (&S3Config{Profile: profile}).Init().ToAwsConfig(&FlagStorage{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cfg.Credentials.Retrieve(t.Context()); err != nil {
				t.Fatal(err)
			}
			provider := cfg.Credentials.(*sharedFileProvider)
			provider.value.CanExpire = true
			provider.value.Expires = time.Now().Add(-time.Minute)
			provider.checkedAt = time.Now()
			value, err := cfg.Credentials.Retrieve(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if value.Expired() || value.CanExpire {
				t.Fatal("expired provider credentials were not refreshed within the stat interval")
			}
		})
	}
}

func TestNewSharedFileCredentialsResolvesConfigProfile(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "other", "AKIAOTHER", "secret-other", "token-other")

	contents := "[profile bucket]\naws_access_key_id=AKIACONFIG\naws_secret_access_key=secret-config\n"
	if err := os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	creds := newSharedFileCredentials("bucket")
	if creds == nil {
		t.Fatal("newSharedFileCredentials() = nil, want the profile resolved from the config file")
	}

	value, err := creds.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIACONFIG" {
		t.Errorf("credentials = %+v, want the profile declared in the config file", value)
	}
}

func TestNewSharedFileCredentialsUnknownProfile(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "other", "AKIAOLD", "secret-old", "token-old")

	creds := newSharedFileCredentials("bucket")
	if creds == nil {
		t.Fatal("newSharedFileCredentials() = nil, want credentials that report the resolution error")
	}

	if _, err := creds.Retrieve(t.Context()); err == nil {
		t.Error("a profile missing from the shared configuration must not resolve to another profile")
	}
}

func TestToAwsConfigProfileCredentialsFollowRotation(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	config := (&S3Config{Profile: "bucket"}).Init()
	awsConfig, err := config.ToAwsConfig(&FlagStorage{})
	if err != nil {
		t.Fatal(err)
	}
	if awsConfig.Credentials == nil {
		t.Fatal("ToAwsConfig() left credentials unset for a profile mount")
	}

	value, err := awsConfig.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIAOLD" {
		t.Fatalf("initial credentials = %+v, want the original profile", value)
	}

	writeSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	awsConfig.Credentials.(*sharedFileProvider).Expire()

	value, err = awsConfig.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIANEW" || value.SessionToken != "token-new" {
		t.Errorf("credentials after expiry = %+v, want the rotated profile", value)
	}
}

func newSharedFileCredentials(profile string) *sharedFileProvider {
	creds := &sharedFileProvider{profile: profile}
	creds.Retrieve(context.Background())
	return creds
}
