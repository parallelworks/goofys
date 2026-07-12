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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func writeAzureConfig(t *testing.T, dir string, contents string) {
	t.Helper()
	err := ioutil.WriteFile(filepath.Join(dir, "config"), []byte(contents), 0600)
	if err != nil {
		t.Fatal(err)
	}
}

func setAzureEnv(t *testing.T, configDir string) {
	t.Helper()
	t.Setenv("AZURE_CONFIG_DIR", configDir)
	t.Setenv("AZURE_STORAGE_ACCOUNT", "")
	t.Setenv("AZURE_STORAGE_KEY", "")
	t.Setenv("AZURE_STORAGE_SAS_TOKEN", "")
}

func TestAzureBlobConfigSasTokenFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	writeAzureConfig(t, dir, "[storage]\nsas_token = ?sv=2021-06-08&se=2026-01-02T15:04:05Z&sr=c&sp=rl&sig=abc\n")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}
	if config.AccountName != "testaccount" {
		t.Errorf("AccountName = %q, want testaccount", config.AccountName)
	}
	if config.AccountKey != "" {
		t.Errorf("AccountKey = %q, want empty", config.AccountKey)
	}
	if config.SasToken == nil {
		t.Fatal("SasToken provider not set")
	}
	token, err := config.SasToken()
	if err != nil {
		t.Fatal(err)
	}
	want := "sv=2021-06-08&se=2026-01-02T15:04:05Z&sr=c&sp=rl&sig=abc"
	if token != want {
		t.Errorf("token = %q, want %q (leading ? stripped)", token, want)
	}
}

func TestAzureBlobConfigSasTokenRotation(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	writeAzureConfig(t, dir, "[storage]\nsas_token = se=2026-01-02T15:04:05Z&sig=old\n")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}
	if config.SasToken == nil {
		t.Fatal("SasToken provider not set")
	}

	writeAzureConfig(t, dir, "[storage]\nsas_token = se=2026-01-03T15:04:05Z&sig=new\n")
	token, err := config.SasToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "se=2026-01-03T15:04:05Z&sig=new" {
		t.Errorf("token = %q, want the rotated token", token)
	}
}

func TestAzureBlobConfigKeyTakesPrecedenceOverSasToken(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	writeAzureConfig(t, dir, "[storage]\nkey = c2VjcmV0\nsas_token = se=2026-01-02T15:04:05Z&sig=abc\n")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}
	if config.AccountKey != "c2VjcmV0" {
		t.Errorf("AccountKey = %q, want the configured key", config.AccountKey)
	}
	if config.SasToken != nil {
		t.Error("SasToken provider set even though a key is configured")
	}
}

func TestAzureBlobConfigSasTokenFromEnv(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	t.Setenv("AZURE_STORAGE_SAS_TOKEN", "se=2026-01-02T15:04:05Z&sig=env")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}
	if config.SasToken == nil {
		t.Fatal("SasToken provider not set")
	}
	token, err := config.SasToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "se=2026-01-02T15:04:05Z&sig=env" {
		t.Errorf("token = %q, want the env token", token)
	}
}

func TestAzureBlobConfigEnvSasTokenTakesPrecedenceOverFile(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	t.Setenv("AZURE_STORAGE_SAS_TOKEN", "se=2026-01-02T15:04:05Z&sig=env")
	writeAzureConfig(t, dir, "[storage]\nsas_token = se=2026-01-02T15:04:05Z&sig=file\n")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}
	if config.SasToken == nil {
		t.Fatal("SasToken provider not set")
	}
	token, err := config.SasToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "se=2026-01-02T15:04:05Z&sig=env" {
		t.Errorf("token = %q, want the env token to win", token)
	}
}

func TestAzureBlobConfigSasTokenIgnoredForDfs(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	writeAzureConfig(t, dir, "[storage]\nsas_token = se=2026-01-02T15:04:05Z&sig=abc\n")

	config, err := AzureBlobConfig("", "container@testaccount.dfs.core.windows.net", "dfs")
	if err == nil {
		t.Error("expected the key-less dfs config to fail like before")
	}
	if config.SasToken != nil {
		t.Error("SasToken provider set for dfs, but ADLv2 cannot sign with a SAS token")
	}
}

func TestAzureBlobConfigSasTokenSurvivesInlineCommentChars(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	writeAzureConfig(t, dir, "[storage]\nsas_token = se=2026-01-02T15:04:05Z&sig=abc;d#ef\n")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}
	token, err := config.SasToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "se=2026-01-02T15:04:05Z&sig=abc;d#ef" {
		t.Errorf("token = %q, want ; and # preserved", token)
	}
}

func TestSasTokenProviderErrorsWhenTokenRemoved(t *testing.T) {
	dir := t.TempDir()
	setAzureEnv(t, dir)
	writeAzureConfig(t, dir, "[storage]\nsas_token = se=2026-01-02T15:04:05Z&sig=abc\n")

	config, err := AzureBlobConfig("", "container@testaccount.blob.core.windows.net", "blob")
	if err != nil {
		t.Fatal(err)
	}

	err = os.Remove(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.SasToken(); err == nil {
		t.Error("expected an error when the sas_token disappears")
	}
}
