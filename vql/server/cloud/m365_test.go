package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIClientRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch n {
		case 1:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
		case 2:
			w.WriteHeader(503)
		default:
			fmt.Fprint(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()

	var waits []time.Duration
	c := newAPIClient("test", srv.Client())
	c.sleep = func(ctx context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return true
	}

	_, data, err := c.do(context.Background(), request{URL: srv.URL})
	require.NoError(t, err)
	assert.Equal(t, `{"ok":true}`, string(data))
	// Honors Retry-After, then backs off.
	assert.Equal(t, []time.Duration{7 * time.Second, 2 * time.Second}, waits)
}

func TestAPIClientGivesUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":{"code":"Authorization_RequestDenied"}}`)
	}))
	defer srv.Close()

	c := newAPIClient("test", srv.Client())
	_, _, err := c.do(context.Background(), request{URL: srv.URL + "/x?$skiptoken=secret"})
	require.Error(t, err)
	assert.Equal(t, 403, statusOf(err))
	// Continuation tokens stay out of logs.
	assert.NotContains(t, err.Error(), "secret")
	assert.Contains(t, describeM365Error(err), "lacks a permission")
}

func TestSeenSet(t *testing.T) {
	s := newSeenSet(time.Hour)
	now := time.Now()
	assert.True(t, s.Add("a", now))
	assert.False(t, s.Add("a", now))
	s.Prune(now.Add(2 * time.Hour))
	assert.Equal(t, 0, s.Len())
	assert.True(t, s.Add("a", now))
}

func TestHaversine(t *testing.T) {
	// London to Paris is about 344 km.
	km := haversineKm(51.5074, -0.1278, 48.8566, 2.3522)
	assert.InDelta(t, 344, km, 3)
	assert.InDelta(t, 0, haversineKm(1, 1, 1, 1), 0.001)
}

func TestIsIdentifier(t *testing.T) {
	assert.True(t, isIdentifier("createdDateTime"))
	assert.False(t, isIdentifier("x ge 1 or true"))
	assert.False(t, isIdentifier(""))
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, 5*time.Second, parseRetryAfter("5"))
	assert.Equal(t, maxRetryAfter, parseRetryAfter("100000"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("garbage"))
	assert.True(t, strings.HasPrefix(redactURL("https://x/y?token=1"), "https://x/y"))
}
