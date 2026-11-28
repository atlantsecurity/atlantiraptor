package authenticators

// Basic (password) authentication checks every request, so there is no
// single "signed in" moment to audit. noteLogin records a Login the
// first time a user is seen from an address, and again after a quiet
// period or a log off, so the audit log shows when each session began.

import (
	"net/http"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
)

// A user active again after this long counts as a new session.
const loginQuietPeriod = 8 * time.Hour

var (
	loginMu   sync.Mutex
	loginSeen = map[string]time.Time{}
)

func loginKey(user, ip string) string { return user + "\x00" + ip }

// noteLogin audits the start of a session.
func noteLogin(config_obj *config_proto.Config, r *http.Request, user, method string) {
	ip := ""
	if parsed := ClientIP(config_obj, r); parsed != nil {
		ip = parsed.String()
	}
	now := time.Now()
	key := loginKey(user, ip)

	loginMu.Lock()
	last, seen := loginSeen[key]
	loginSeen[key] = now
	if len(loginSeen) > 10000 {
		for k, t := range loginSeen {
			if now.Sub(t) > loginQuietPeriod {
				delete(loginSeen, k)
			}
		}
	}
	loginMu.Unlock()

	if seen && now.Sub(last) < loginQuietPeriod {
		return
	}
	err := services.LogAudit(r.Context(), config_obj, user, "Login",
		ordereddict.NewDict().
			Set("method", method).
			Set("remote", r.RemoteAddr).
			Set("client_ip", ip).
			Set("user_agent", r.UserAgent()))
	if err != nil {
		logging.GetLogger(config_obj, &logging.FrontendComponent).
			Error("LogAudit: Login %v %v", user, r.RemoteAddr)
	}
}

// forgetLogins makes the next request of a user count as a new login.
func forgetLogins(user string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	for k := range loginSeen {
		if len(k) > len(user) && k[:len(user)+1] == user+"\x00" {
			delete(loginSeen, k)
		}
	}
}
