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
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

const sharedCredentialsStatInterval = 10 * time.Second

var credentialsLog = GetLogger("s3")

type sharedFileState struct {
	modTime time.Time
	size    int64
}

func (s sharedFileState) equal(other sharedFileState) bool {
	return s.size == other.size && s.modTime.Equal(other.modTime)
}

type sharedFileProvider struct {
	mu          sync.Mutex
	profile     string
	loadOptions []func(*config.LoadOptions) error
	value       aws.Credentials
	state       sharedFileState
	loaded      bool
	expired     bool
	unreadable  bool
	checkedAt   time.Time
}

func (p *sharedFileProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isExpired() {
		return p.value, nil
	}
	state, stated := p.fileState()

	cfg, err := config.LoadDefaultConfig(ctx, sharedConfigLoadOptions(p.profile, p.loadOptions)...)
	if err != nil {
		return p.keepLoaded(err)
	}

	value, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return p.keepLoaded(err)
	}

	p.value = value
	p.loaded = true
	p.expired = false
	p.unreadable = !stated
	p.checkedAt = time.Now()
	if stated {
		p.state = state
	}
	return value, nil
}

func (p *sharedFileProvider) IsExpired() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isExpired()
}

func (p *sharedFileProvider) Expire() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expired = true
}

func (p *sharedFileProvider) isExpired() bool {
	if !p.loaded || p.expired {
		return true
	}

	if p.value.Expired() {
		p.expired = true
		return true
	}

	now := time.Now()
	if now.Sub(p.checkedAt) < sharedCredentialsStatInterval {
		return false
	}
	p.checkedAt = now

	state, stated := p.fileState()
	if !stated {
		if !p.unreadable {
			p.unreadable = true
			credentialsLog.Warnf("cannot stat %v, keeping the credentials loaded for profile %v",
				sharedCredentialsFilename(), p.profile)
		}
		return false
	}
	p.unreadable = false

	p.expired = !p.state.equal(state)
	return p.expired
}

func (p *sharedFileProvider) keepLoaded(err error) (aws.Credentials, error) {
	if !p.loaded {
		return aws.Credentials{}, err
	}

	p.expired = false
	p.checkedAt = time.Now()
	credentialsLog.Warnf("cannot reload credentials for profile %v, keeping the previous credentials: %v",
		p.profile, err)
	return p.value, nil
}

func sharedConfigLoadOptions(profile string, base []func(*config.LoadOptions) error) []func(*config.LoadOptions) error {
	options := append([]func(*config.LoadOptions) error{}, base...)
	if profile != "" {
		options = append(options, config.WithSharedConfigProfile(profile))
	}
	return options
}

func (p *sharedFileProvider) fileState() (sharedFileState, bool) {
	info, err := os.Stat(sharedCredentialsFilename())
	if err != nil {
		return sharedFileState{}, false
	}
	return sharedFileState{modTime: info.ModTime(), size: info.Size()}, true
}

func sharedCredentialsFilename() string {
	if filename := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); filename != "" {
		return filename
	}
	return config.DefaultSharedCredentialsFilename()
}
