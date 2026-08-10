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
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
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
	mu         sync.Mutex
	profile    string
	resolved   *credentials.Credentials
	value      credentials.Value
	state      sharedFileState
	loaded     bool
	expired    bool
	unreadable bool
	checkedAt  time.Time
}

func newSharedFileCredentials(profile string) *credentials.Credentials {
	creds := credentials.NewCredentials(&sharedFileProvider{profile: profile})
	if _, err := creds.Get(); err != nil {
		credentialsLog.Warnf("cannot resolve credentials for profile %v: %v", profile, err)
	}
	return creds
}

func (p *sharedFileProvider) Retrieve() (credentials.Value, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	state, stated := p.fileState()

	sess, err := session.NewSessionWithOptions(session.Options{
		Profile:           p.profile,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return p.keepLoaded(err)
	}

	value, err := sess.Config.Credentials.Get()
	if err != nil {
		return p.keepLoaded(err)
	}

	p.resolved = sess.Config.Credentials
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

	if !p.loaded || p.expired {
		return true
	}

	now := time.Now()
	if now.Sub(p.checkedAt) < sharedCredentialsStatInterval {
		return false
	}
	p.checkedAt = now

	if p.resolved.IsExpired() {
		p.expired = true
		return true
	}

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

func (p *sharedFileProvider) keepLoaded(err error) (credentials.Value, error) {
	if !p.loaded {
		return credentials.Value{}, err
	}

	p.expired = false
	p.checkedAt = time.Now()
	credentialsLog.Warnf("cannot reload credentials for profile %v, keeping the previous credentials: %v",
		p.profile, err)
	return p.value, nil
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
	return defaults.SharedCredentialsFilename()
}
