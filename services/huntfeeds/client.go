package huntfeeds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"www.velocidex.com/golang/velociraptor/config"
)

// DefaultFeedURL is Atlant Security's feed service.
const DefaultFeedURL = "https://feeds.atlantsecurity.com/v1/feed"

// FeedURLEnv points the server at another feed service (Atlant's
// staging service, for example). Content must still be signed with one
// of the keys compiled into the binary, so this cannot be used to load
// anyone else's content.
const FeedURLEnv = "ATLANTIRAPTOR_FEED_URL"

// SubscribeURL is shown on the console when there is no subscription.
const SubscribeURL = "https://atlantsecurity.com/"

// httpTransport and testInsecure let tests use an httptest server.
var (
	httpTransport http.RoundTripper
	testInsecure  = false
)

func feedURL() string {
	if v := strings.TrimSpace(os.Getenv(FeedURLEnv)); v != "" {
		return v
	}
	return DefaultFeedURL
}

// rejection is a definite answer from the feed service about the
// licence key (as opposed to a network problem).
type rejection struct {
	state   string // StateInvalid or StateExpired
	message string
}

func (self *rejection) Error() string { return self.message }

func checkURL(u *url.URL) error {
	if u == nil || u.Host == "" {
		return errors.New("the feed URL is not valid")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && testInsecure) {
		return fmt.Errorf("the feed URL must use https, not %v", u.Scheme)
	}
	return nil
}

func userAgent() string {
	v := config.ReleaseVersion()
	if v == "" {
		v = "dev"
	}
	return "Atlantiraptor-feeds/" + v
}

// fetch asks the feed service for the bundle issued to licence_key.
func fetch(ctx context.Context, licence_key, server_id string) ([]byte, error) {
	address := feedURL()
	u, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("the feed URL is not valid: %w", err)
	}
	if err := checkURL(u); err != nil {
		return nil, err
	}
	host := u.Host

	transport := httpTransport
	if transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = http.ProxyFromEnvironment
		transport = t
	}
	client := &http.Client{
		Timeout:   2 * time.Minute,
		Transport: transport,
		// The licence key goes in a header: only follow redirects on the
		// same host over https.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if err := checkURL(req.URL); err != nil {
				return err
			}
			if req.URL.Host != host {
				return fmt.Errorf("refusing redirect to %v", req.URL.Host)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+licence_key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("X-Atlantiraptor-Version", config.ReleaseVersion())
	req.Header.Set("X-Atlantiraptor-Feed-Format", fmt.Sprint(FormatVersion))
	if server_id != "" {
		req.Header.Set("X-Atlantiraptor-Server", server_id)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching the feed service: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the feed: %w", err)
	}
	if len(body) > maxBundleSize {
		return nil, errors.New("the feed is too large")
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, &rejection{state: StateInvalid,
			message: serviceMessage(body, "The feed service did not accept this licence key.")}
	case http.StatusPaymentRequired, http.StatusGone:
		return nil, &rejection{state: StateExpired,
			message: serviceMessage(body, "The subscription for this licence key has ended.")}
	default:
		return nil, fmt.Errorf("the feed service answered %v: %v", resp.Status,
			serviceMessage(body, "try again later"))
	}
}

// serviceMessage takes {"message": "..."} from an error response.
func serviceMessage(body []byte, fallback string) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil {
		msg := strings.TrimSpace(m.Message)
		if msg != "" {
			if len(msg) > 300 {
				msg = msg[:300]
			}
			return msg
		}
	}
	return fallback
}
