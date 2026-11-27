package cloud

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOktaBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://acme.okta.com":                     "https://acme.okta.com",
		"acme.okta.com":                             "https://acme.okta.com",
		"https://ACME.okta-emea.com/":               "https://acme.okta-emea.com",
		"https://acme.oktapreview.com/app/UserHome": "https://acme.oktapreview.com",
		"https://agency.okta-gov.com":               "https://agency.okta-gov.com",
	} {
		got, err := oktaBase(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	for _, in := range []string{
		"https://evil.example",
		"https://acme.okta.com.evil.example",
		"https://acme.okta.com@evil.example",
		"http://acme.okta.com",
		"https://acme.okta.com:8443",
		"https://login.acme.com",
		"https://okta.com",
	} {
		_, err := oktaBase(in)
		assert.Error(t, err, in)
	}
}

func TestOktaNextLink(t *testing.T) {
	base := "https://acme.okta.com"
	h := http.Header{}
	h.Add("Link", `<https://acme.okta.com/api/v1/logs?limit=1000>; rel="self"`)
	h.Add("Link", `<https://acme.okta.com/api/v1/logs?after=abc>; rel="next"`)
	assert.Equal(t, "https://acme.okta.com/api/v1/logs?after=abc", oktaNextLink(h, base))

	h = http.Header{}
	h.Add("Link", `<https://acme.okta.com.evil.example/api/v1/logs?after=abc>; rel="next"`)
	assert.Equal(t, "", oktaNextLink(h, base))

	assert.Equal(t, "", oktaNextLink(http.Header{}, base))
}

// The token is only ever sent to the org's own host.
func TestOktaTransportRefusesOtherHosts(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer server.Close()

	transport := &oktaTransport{base: http.DefaultTransport, host: "acme.okta.com", token: "secret"}
	client := &http.Client{Transport: transport}
	_, err := client.Get(server.URL)
	assert.Error(t, err)
	assert.Equal(t, "", got)
}
