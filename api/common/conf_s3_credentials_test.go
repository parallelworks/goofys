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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
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

	value, err := creds.Get()
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIAOLD" || value.SessionToken != "token-old" {
		t.Fatalf("initial credentials = %+v, want the original profile", value)
	}

	writeSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	creds.Expire()

	value, err = creds.Get()
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
	creds := credentials.NewCredentials(provider)

	value, err := creds.Get()
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIAOLD" {
		t.Fatalf("initial credentials = %+v, want the original profile", value)
	}

	rotateSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	provider.checkedAt = time.Now().Add(-sharedCredentialsStatInterval)

	value, err = creds.Get()
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
	if _, err := provider.Retrieve(); err != nil {
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
	if _, err := provider.Retrieve(); err != nil {
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
	if _, err := provider.Retrieve(); err != nil {
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
	if _, err := provider.Retrieve(); err != nil {
		t.Fatal(err)
	}

	rotateSharedCredentials(t, path, "other", "AKIANEW", "secret-new", "token-new")

	value, err := provider.Retrieve()
	if err != nil {
		t.Fatalf("Retrieve() = %v, want the previously loaded credentials", err)
	}
	if value.AccessKeyID != "AKIAOLD" {
		t.Errorf("credentials after a failed reload = %+v, want the previously loaded profile", value)
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

	value, err := creds.Get()
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

	if _, err := creds.Get(); err == nil {
		t.Error("a profile missing from the shared configuration must not resolve to another profile")
	}
}

func TestToAwsConfigProfileCredentialsFollowRotation(t *testing.T) {
	path := sharedCredentialsFile(t)
	writeSharedCredentials(t, path, "bucket", "AKIAOLD", "secret-old", "token-old")

	previousSession := s3Session
	s3Session = nil
	t.Cleanup(func() { s3Session = previousSession })

	config := (&S3Config{Profile: "bucket"}).Init()
	awsConfig, err := config.ToAwsConfig(&FlagStorage{})
	if err != nil {
		t.Fatal(err)
	}
	if awsConfig.Credentials == nil {
		t.Fatal("ToAwsConfig() left credentials unset for a profile mount")
	}

	value, err := awsConfig.Credentials.Get()
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIAOLD" {
		t.Fatalf("initial credentials = %+v, want the original profile", value)
	}

	writeSharedCredentials(t, path, "bucket", "AKIANEW", "secret-new", "token-new")
	awsConfig.Credentials.Expire()

	value, err = awsConfig.Credentials.Get()
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessKeyID != "AKIANEW" || value.SessionToken != "token-new" {
		t.Errorf("credentials after expiry = %+v, want the rotated profile", value)
	}
}
