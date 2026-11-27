package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"www.velocidex.com/golang/velociraptor/artifacts"
	"www.velocidex.com/golang/velociraptor/vql/networking"
	"www.velocidex.com/golang/vfilter"
)

// Token sources are cached per credential and audience so that hunts
// that call a plugin once per user (thousands of calls) fetch one token
// an hour rather than one per call.
var (
	tokenCacheMu sync.Mutex
	tokenCache   = make(map[string]oauth2.TokenSource)
)

func cacheKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cachedTokenSource(key string,
	make_source func() oauth2.TokenSource) oauth2.TokenSource {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()

	ts, pres := tokenCache[key]
	if !pres {
		ts = oauth2.ReuseTokenSource(nil, make_source())
		tokenCache[key] = ts
	}
	return ts
}

// resetTokenCache is used by tests.
func resetTokenCache() {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	tokenCache = make(map[string]oauth2.TokenSource)
}

// baseTransport honors the server's proxy and CA settings.
func baseTransport(scope vfilter.Scope) (http.RoundTripper, error) {
	config_obj, _ := artifacts.GetConfig(scope)
	return networking.GetHttpTransport(config_obj, "")
}

// tokenContext carries the http client the oauth2 package uses to reach
// the token endpoint. It is a background context because cached token
// sources outlive the query that created them.
func tokenContext(transport http.RoundTripper) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient,
		&http.Client{Transport: transport, Timeout: 30 * time.Second})
}

// authClient returns an http client that adds the bearer token from ts.
func authClient(transport http.RoundTripper, ts oauth2.TokenSource) *http.Client {
	return &http.Client{
		Transport: &oauth2.Transport{Source: ts, Base: transport},
		Timeout:   5 * time.Minute,
	}
}
