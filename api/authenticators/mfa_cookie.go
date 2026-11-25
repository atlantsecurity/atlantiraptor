package authenticators

// The 2FA session cookie proves that this browser passed the second
// factor for this user recently. It is an HMAC over (user, generation,
// expiry) with a key derived from the server private key under its own
// label, so it can't be confused with the CSRF key.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	MFACookieName = "atl_mfa"
	MFASessionTTL = 12 * time.Hour
)

func mfaKey(config_obj *config_proto.Config) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("atlantiraptor-mfa-session-v1\x00"))
	if config_obj != nil && config_obj.Frontend != nil {
		_, _ = h.Write([]byte(config_obj.Frontend.PrivateKey))
	}
	return h.Sum(nil)
}

func mfaSign(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// NewMFACookieValue returns the signed cookie value for a user.
func NewMFACookieValue(config_obj *config_proto.Config, username string,
	generation int64, now time.Time) string {
	payload := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(username)),
		strconv.FormatInt(generation, 10),
		strconv.FormatInt(now.Add(MFASessionTTL).Unix(), 10),
	}, ".")
	return payload + "." + mfaSign(mfaKey(config_obj), payload)
}

// VerifyMFACookieValue checks the signature, the user, the generation
// and the expiry.
func VerifyMFACookieValue(config_obj *config_proto.Config, value, username string,
	generation int64, now time.Time) error {
	if !mfaKeyAvailable(config_obj) {
		return fmt.Errorf("no server key")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return fmt.Errorf("malformed session")
	}
	payload := strings.Join(parts[:3], ".")
	expected := mfaSign(mfaKey(config_obj), payload)
	if !hmac.Equal([]byte(expected), []byte(parts[3])) {
		return fmt.Errorf("bad signature")
	}
	user, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !utils.UsernamesEqual(string(user), username) {
		return fmt.Errorf("session belongs to another user")
	}
	gen, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || gen != generation {
		return fmt.Errorf("session revoked")
	}
	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || now.Unix() >= expiry {
		return fmt.Errorf("session expired")
	}
	return nil
}

// The session key must come from a real server key; without one the
// cookie could be forged, so no session is ever issued or accepted.
func mfaKeyAvailable(config_obj *config_proto.Config) bool {
	return config_obj != nil && config_obj.Frontend != nil && config_obj.Frontend.PrivateKey != ""
}

func setMFACookie(w http.ResponseWriter, r *http.Request, config_obj *config_proto.Config,
	username string, generation int64) {
	if !mfaKeyAvailable(config_obj) {
		return
	}
	// Secure unless the console is deliberately served over plain HTTP
	// (for example behind a TLS-terminating proxy).
	plain := config_obj.GUI != nil && config_obj.GUI.UsePlainHttp && r.TLS == nil
	http.SetCookie(w, &http.Cookie{
		Name:     MFACookieName,
		Value:    NewMFACookieValue(config_obj, username, generation, time.Now()),
		Path:     "/",
		MaxAge:   int(MFASessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   !plain,
		SameSite: http.SameSiteStrictMode,
	})
}

func mfaCookieValid(r *http.Request, config_obj *config_proto.Config,
	username string, record *MFARecord) bool {
	if !mfaKeyAvailable(config_obj) {
		return false
	}
	cookie, err := r.Cookie(MFACookieName)
	if err != nil {
		return false
	}
	return VerifyMFACookieValue(config_obj, cookie.Value, username,
		record.Generation, time.Now()) == nil
}
