/*
Atlantiraptor - cloud breach hunting.
Copyright (C) 2026 Atlant Security EOOD.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package cloud holds the VQL plugins that read identity and audit logs
// from cloud and SaaS tenants (Microsoft 365 / Entra ID, Google Workspace,
// Okta, AWS) so that the server can hunt for cloud breach artifacts the
// same way it hunts on endpoints.
//
// All plugins in this package run on the server, use credentials from the
// secrets service and only ever read: none of them can change anything in
// the tenant.
package cloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
)

const (
	// Never honor a Retry-After longer than this.
	maxRetryAfter = 2 * time.Minute

	// Largest response body we read. Audit content blobs are a few MB at
	// most; this only stops a broken or hostile endpoint from exhausting
	// memory.
	maxResponseBody = 128 * 1024 * 1024

	// How much of an error body ends up in the log.
	maxErrorBody = 2048

	defaultMaxRetries = 6
)

// APIError is returned for a non-2xx answer that was not retried away.
type APIError struct {
	StatusCode int
	URL        string
	Body       string
}

func (self *APIError) Error() string {
	return fmt.Sprintf("%v returned HTTP %d: %s", redactURL(self.URL),
		self.StatusCode, self.Body)
}

func statusOf(err error) int {
	var api_err *APIError
	if errors.As(err, &api_err) {
		return api_err.StatusCode
	}
	return 0
}

// Query strings may carry continuation tokens; keep logs short and free of
// them.
func redactURL(u string) string {
	if idx := strings.IndexByte(u, '?'); idx > 0 {
		return u[:idx]
	}
	return u
}

// apiClient wraps an http.Client that already authenticates its requests
// (an oauth2 transport, or a header-adding round tripper) with retries
// for throttling and transient server errors.
type apiClient struct {
	name       string
	client     *http.Client
	maxRetries int

	// Sleep is replaceable in tests.
	sleep func(ctx context.Context, d time.Duration) bool
}

func newAPIClient(name string, client *http.Client) *apiClient {
	return &apiClient{
		name:       name,
		client:     client,
		maxRetries: defaultMaxRetries,
		sleep:      sleepCtx,
	}
}

type request struct {
	Method  string
	URL     string
	Body    []byte
	Headers map[string]string
}

// do issues the request, retrying 429 and 5xx answers. It returns the
// final response (body already read and closed) and its body.
func (self *apiClient) do(ctx context.Context, req request) (
	*http.Response, []byte, error) {

	if req.Method == "" {
		req.Method = "GET"
	}

	for attempt := 0; ; attempt++ {
		var body io.Reader
		if req.Body != nil {
			body = strings.NewReader(string(req.Body))
		}

		http_req, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
		if err != nil {
			return nil, nil, err
		}
		http_req.Header.Set("Accept", "application/json")
		if req.Body != nil {
			http_req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range req.Headers {
			http_req.Header.Set(k, v)
		}

		resp, err := self.client.Do(http_req)
		if err != nil {
			if ctx.Err() != nil || attempt >= self.maxRetries {
				return nil, nil, err
			}
			if !self.sleep(ctx, backoff(attempt)) {
				return nil, nil, ctx.Err()
			}
			continue
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if len(data) > maxResponseBody {
			return nil, nil, fmt.Errorf("%v: response from %v is larger than %d bytes",
				self.name, redactURL(req.URL), maxResponseBody)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, data, nil
		}

		retryable := resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500
		if !retryable || attempt >= self.maxRetries {
			return resp, data, &APIError{
				StatusCode: resp.StatusCode,
				URL:        req.URL,
				Body:       truncate(string(data), maxErrorBody),
			}
		}

		wait := parseRetryAfter(resp.Header.Get("Retry-After"))
		if wait == 0 {
			wait = backoff(attempt)
		}
		if !self.sleep(ctx, wait) {
			return nil, nil, ctx.Err()
		}
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func backoff(attempt int) time.Duration {
	if attempt > 7 {
		attempt = 7
	}
	d := time.Second << uint(attempt)
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}

	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}

	if d < 0 {
		return 0
	}
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// seenSet remembers keys for a while so that follow mode, which re-reads
// an overlapping window on every poll, emits each record once.
type seenSet struct {
	mu   sync.Mutex
	ttl  time.Duration
	keys map[string]time.Time
}

func newSeenSet(ttl time.Duration) *seenSet {
	return &seenSet{ttl: ttl, keys: make(map[string]time.Time)}
}

// Add returns true when the key was not seen before.
func (self *seenSet) Add(key string, now time.Time) bool {
	self.mu.Lock()
	defer self.mu.Unlock()

	if _, pres := self.keys[key]; pres {
		return false
	}
	self.keys[key] = now
	return true
}

func (self *seenSet) Prune(now time.Time) {
	self.mu.Lock()
	defer self.mu.Unlock()

	for k, v := range self.keys {
		if now.Sub(v) > self.ttl {
			delete(self.keys, k)
		}
	}
}

func (self *seenSet) Len() int {
	self.mu.Lock()
	defer self.mu.Unlock()
	return len(self.keys)
}

// getSecret loads a secret of the given type for the scope's principal.
func getSecret(ctx context.Context, scope vfilter.Scope,
	type_name, name string) (*services.Secret, error) {

	config_obj, ok := vql_subsystem.GetServerConfig(scope)
	if !ok {
		return nil, errors.New("secrets may only be used on the server")
	}

	secrets_service, err := services.GetSecretsService(config_obj)
	if err != nil {
		return nil, err
	}

	principal := vql_subsystem.GetPrincipal(scope)
	return secrets_service.GetSecret(ctx, principal, type_name, name)
}

// secretsEnforced is true when the server only allows credentials from
// the secrets service and none was named.
func secretsEnforced(scope vfilter.Scope, secret string) error {
	config_obj, ok := vql_subsystem.GetServerConfig(scope)
	if !ok || config_obj.Security == nil {
		return nil
	}
	if config_obj.Security.VqlMustUseSecrets && secret == "" {
		return utils.SecretsEnforced
	}
	return nil
}

// pollWindow tracks the start of the next follow-mode read. Each poll
// re-reads `overlap` before the previous end so records that the
// provider publishes late are still picked up; seenSet drops repeats.
type pollWindow struct {
	next    time.Time
	overlap time.Duration
}

func (self *pollWindow) Start() time.Time {
	return self.next.Add(-self.overlap)
}

func (self *pollWindow) Advance(end time.Time) {
	if end.After(self.next) {
		self.next = end
	}
}
