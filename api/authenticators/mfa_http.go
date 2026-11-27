package authenticators

// HTTP endpoints for two-factor authentication with basic auth.
//
// Password-only routes (the user has typed their password but not yet
// passed the second factor):
//   GET  /app/mfa.html              the code entry page
//   POST /api/v1/atl/mfa/verify     check a TOTP or recovery code
//   GET  /api/v1/atl/mfa/whoami     enrolment and session status
//
// Fully authenticated routes (password and, if enrolled, second factor):
//   /api/v1/atl/mfa/manage/...      enrol, confirm, disable, recovery
//                                   codes, admin reset
//
// Requests for anything else from an enrolled user without a valid 2FA
// session are refused by the basic authenticator (see mfaGate).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	csrf "filippo.io/csrf/gorilla"
	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	api_utils "www.velocidex.com/golang/velociraptor/api/utils"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const maxBody = 4096

func rootConfig() (*config_proto.Config, error) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return nil, err
	}
	return org_manager.GetOrgConfig(services.ROOT_ORG_ID)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

func readJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody)).Decode(v)
}

func audit(ctx context.Context, config_obj *config_proto.Config, user, op string, details *ordereddict.Dict) {
	if err := services.LogAudit(ctx, config_obj, user, op, details); err != nil {
		logger := logging.GetLogger(config_obj, &logging.FrontendComponent)
		logger.Error("%v %v", op, user)
	}
}

func userFromContext(r *http.Request) string {
	if v, ok := r.Context().Value(constants.GRPC_USER_CONTEXT).(string); ok {
		return utils.UnQuote(v)
	}
	return ""
}

// passwordOnly checks the basic auth password but not the second factor.
func passwordOnly(config_obj *config_proto.Config, next http.HandlerFunc) http.Handler {
	return api_utils.HandlerFunc(nil, func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		users_manager := services.GetUserManager()
		user_record, err := users_manager.GetUserWithHashes(r.Context(), username, username)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}
		ok, err = users_manager.VerifyPassword(r.Context(), user_record.Name, user_record.Name, password)
		if !ok || err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), constants.GRPC_USER_CONTEXT, utils.Quote(user_record.Name))
		next(w, r.WithContext(ctx))
	})
}

// Break-glass: starting the server with this environment variable set
// to 1 turns the second-factor check off, for when every administrator
// has lost their factor. It needs access to the server machine itself.
const MFADisableEnv = "ATLANTIRAPTOR_DISABLE_MFA"

func mfaDisabled() bool {
	return os.Getenv(MFADisableEnv) == "1"
}

// mfaGate is called by the basic authenticator after the password and
// org checks. It returns true when the request may proceed.
func mfaGate(w http.ResponseWriter, r *http.Request, config_obj *config_proto.Config, username string) bool {
	if mfaDisabled() {
		return true
	}
	root, err := rootConfig()
	if err != nil {
		jsonError(w, http.StatusForbidden, "Two-factor status could not be checked.")
		return false
	}
	record, err := LoadMFA(root, username)
	if err != nil {
		audit(r.Context(), root, username, "mfa_record_unreadable",
			ordereddict.NewDict().Set("error", err.Error()).Set("remote", r.RemoteAddr))
		jsonError(w, http.StatusForbidden, "Two-factor status could not be read. Ask an administrator.")
		return false
	}
	reason := ""
	if record.Enrolled() {
		if mfaCookieValid(r, root, username, record) {
			return true
		}
		// Passed from this address recently: don't ask again.
		if mfaIPTrusted(r, root, record) {
			return true
		}
		reason = "mfa_required"
	} else {
		// Not enrolled: allowed only when the policy does not require
		// 2FA for this user; otherwise they must enrol first, which the
		// 2FA page lets them do with their password.
		if !mfaRequiredFor(root, username) {
			return true
		}
		reason = "mfa_enroll_required"
	}

	// 403, never 401: a 401 would make the browser ask for the
	// password again instead of the second factor.
	if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, api_utils.GetBasePath(config_obj, "/api/")) {
		target := api_utils.GetBasePath(config_obj, "/app/mfa.html") + "?return=" +
			url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, target, http.StatusSeeOther)
		return false
	}
	jsonError(w, http.StatusForbidden, reason)
	return false
}

// AddMFAHandlers installs the 2FA routes. wrap adds IP filtering and
// CSRF protection; full wraps a handler with complete authentication.
func AddMFAHandlers(config_obj *config_proto.Config, mux *api_utils.ServeMux,
	wrap func(http.Handler) http.Handler,
	full func(http.Handler, acls.ACL_PERMISSION) http.Handler) {

	mux.Handle(api_utils.GetBasePath(config_obj, "/app/mfa.html"),
		wrap(passwordOnly(config_obj, mfaPage(config_obj))))
	mux.Handle(api_utils.GetBasePath(config_obj, "/api/v1/atl/mfa/"),
		wrap(passwordOnly(config_obj, mfaPublicAPI(config_obj))))
	mux.Handle(api_utils.GetBasePath(config_obj, "/api/v1/atl/mfa/manage/"),
		wrap(full(api_utils.HandlerFunc(nil, mfaManageAPI(config_obj)), acls.READ_RESULTS)))
}

func mfaPublicAPI(config_obj *config_proto.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := userFromContext(r)
		root, err := rootConfig()
		if err != nil || user == "" {
			jsonError(w, http.StatusInternalServerError, "Server not ready.")
			return
		}
		record, err := LoadMFA(root, user)
		if err != nil {
			jsonError(w, http.StatusForbidden, "Two-factor status could not be read. Ask an administrator.")
			return
		}

		switch strings.TrimPrefix(r.URL.Path, api_utils.GetBasePath(config_obj, "/api/v1/atl/mfa/")) {
		case "whoami":
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"user":     user,
				"enrolled": record.Enrolled(),
				"required": mfaDisabled() == false && mfaRequiredFor(root, user),
				"verified": record.Enrolled() && (mfaCookieValid(r, root, user, record) ||
					mfaIPTrusted(r, root, record)),
			})

		case "verify":
			if r.Method != http.MethodPost {
				jsonError(w, http.StatusMethodNotAllowed, "POST only")
				return
			}
			verifyCode(w, r, root, user, record)

		// Enrolment with the password only, so users who must use 2FA
		// can set it up at sign in. Both steps refuse once a factor is
		// enrolled: changing an existing factor needs a current code.
		case "enroll/begin":
			if r.Method != http.MethodPost {
				jsonError(w, http.StatusMethodNotAllowed, "POST only")
				return
			}
			beginTOTP(w, r, root, user)

		case "enroll/confirm":
			if r.Method != http.MethodPost {
				jsonError(w, http.StatusMethodNotAllowed, "POST only")
				return
			}
			confirmTOTP(w, r, root, user)

		default:
			jsonError(w, http.StatusNotFound, "Not found")
		}
	}
}

// codeCheckMu serialises every code check, so parallel requests can't
// all pass the attempt limit before any failure is counted.
var codeCheckMu sync.Mutex

func verifyCode(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string, record *MFARecord) {
	codeCheckMu.Lock()
	defer codeCheckMu.Unlock()
	if !record.Enrolled() {
		jsonError(w, http.StatusBadRequest, errNotEnrolledLabel)
		return
	}
	now := time.Now()
	if tooManyFailures(user, now) {
		audit(r.Context(), root, user, "mfa_rate_limited", ordereddict.NewDict().Set("remote", r.RemoteAddr))
		jsonError(w, http.StatusTooManyRequests, errTooManyAttempts)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &body); err != nil {
		jsonError(w, http.StatusBadRequest, "Bad request")
		return
	}
	apply, ok := verifySecondFactor(record, body.Code, now)
	if !ok {
		recordFailure(user, now)
		audit(r.Context(), root, user, "mfa_verify_failed", ordereddict.NewDict().Set("remote", r.RemoteAddr))
		jsonError(w, http.StatusForbidden, errInvalidCode)
		return
	}
	apply, remembered := withRememberedIP(r, root, apply)
	updated, err := UpdateMFA(root, user, apply)
	if err != nil {
		recordFailure(user, now)
		jsonError(w, http.StatusForbidden, errInvalidCode)
		return
	}
	clearFailures(user)
	setMFACookie(w, r, root, user, updated.Generation)
	audit(r.Context(), root, user, "mfa_verified", ordereddict.NewDict().
		Set("remote", r.RemoteAddr).Set("remembered_ip", remembered))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "recovery_codes_left": len(updated.RecoveryHashes)})
}

func mfaManageAPI(config_obj *config_proto.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := userFromContext(r)
		root, err := rootConfig()
		if err != nil || user == "" {
			jsonError(w, http.StatusInternalServerError, "Server not ready.")
			return
		}
		action := strings.TrimPrefix(r.URL.Path, api_utils.GetBasePath(config_obj, "/api/v1/atl/mfa/manage/"))
		if action != "status" && action != "user_status" && action != "policy" && r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}

		switch action {
		case "status":
			record, err := LoadMFA(root, user)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "Could not read two-factor status.")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"enrolled":            record.Enrolled(),
				"required":            mfaRequiredFor(root, user),
				"recovery_codes_left": recoveryLeft(record),
			})

		case "policy":
			policyAction(w, r, root, user)

		case "totp/begin":
			beginTOTP(w, r, root, user)

		case "totp/confirm":
			confirmTOTP(w, r, root, user)

		case "disable":
			if mfaRequiredFor(root, user) {
				jsonError(w, http.StatusConflict, "Two-factor sign in is required for your account by the server policy.")
				return
			}
			disableTOTP(w, r, root, user)

		case "recovery/regenerate":
			regenerateRecovery(w, r, root, user)

		case "user_status", "admin_reset":
			adminAction(w, r, root, user, action)

		default:
			jsonError(w, http.StatusNotFound, "Not found")
		}
	}
}

// policyAction reads (any signed-in user) or changes (server admins of
// the root org) who must use two-factor sign in.
func policyAction(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string) {
	if r.Method == http.MethodGet {
		p, err := LoadMFAPolicy(root)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Could not read the 2FA policy.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"policy": p, "break_glass_active": mfaDisabled()})
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "GET or POST")
		return
	}
	ok, err := services.CheckAccess(root, user, acls.SERVER_ADMIN)
	if err != nil || !ok {
		jsonError(w, http.StatusForbidden, "Only server administrators can change the 2FA policy.")
		return
	}
	var body MFAPolicy
	if err := readJSON(r, &body); err != nil {
		jsonError(w, http.StatusBadRequest, "Bad request")
		return
	}
	saved, err := SaveMFAPolicy(root, body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	audit(r.Context(), root, user, "mfa_policy_update", ordereddict.NewDict().
		Set("mode", saved.Mode).Set("roles", saved.Roles).Set("groups", saved.Groups).
		Set("remember_ip_days", saved.RememberIPDays))
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": saved})
}
func recoveryLeft(r *MFARecord) int {
	if r == nil {
		return 0
	}
	return len(r.RecoveryHashes)
}

// errAlreadyEnrolled stops a hijacked session from swapping the factor:
// turning it off first needs a current code.
const errAlreadyEnrolled = "Two-factor sign in is already on. Turn it off with a current code first."

func beginTOTP(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string) {
	if existing, err := LoadMFA(root, user); err != nil || existing.Enrolled() {
		jsonError(w, http.StatusConflict, errAlreadyEnrolled)
		return
	}
	key, err := newTOTPKey(user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not create a secret.")
		return
	}
	if _, err := UpdateMFA(root, user, func(rec *MFARecord) error {
		rec.PendingTOTPSecret = key.Secret()
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not save the secret.")
		return
	}
	qr := ""
	if img, err := key.Image(240, 240); err == nil {
		var buf bytes.Buffer
		if png.Encode(&buf, img) == nil {
			qr = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": key.Secret(), "otpauth_url": key.URL(), "qr_png": qr,
	})
}

func confirmTOTP(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string) {
	codeCheckMu.Lock()
	defer codeCheckMu.Unlock()
	var body struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &body); err != nil {
		jsonError(w, http.StatusBadRequest, "Bad request")
		return
	}
	now := time.Now()
	if tooManyFailures(user, now) {
		jsonError(w, http.StatusTooManyRequests, errTooManyAttempts)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not create recovery codes.")
		return
	}
	enrol, _ := withRememberedIP(r, root, func(rec *MFARecord) error {
		if rec.TOTPSecret != "" {
			return fmt.Errorf("already enrolled")
		}
		if rec.PendingTOTPSecret == "" {
			return fmt.Errorf("no enrolment in progress")
		}
		step := totpStep(rec.PendingTOTPSecret, body.Code, now)
		if step < 0 {
			return fmt.Errorf("invalid code")
		}
		rec.TOTPSecret = rec.PendingTOTPSecret
		rec.PendingTOTPSecret = ""
		rec.TOTPLastStep = step
		rec.RecoveryHashes = hashes
		rec.Generation++
		return nil
	})
	updated, err := UpdateMFA(root, user, enrol)
	if err != nil {
		recordFailure(user, now)
		jsonError(w, http.StatusBadRequest, "That code did not match. Check the time on your phone and try again.")
		return
	}
	clearFailures(user)
	// Keep the current browser signed in under the new generation.
	setMFACookie(w, r, root, user, updated.Generation)
	audit(r.Context(), root, user, "mfa_enabled", ordereddict.NewDict().Set("method", "totp"))
	writeJSON(w, http.StatusOK, map[string]interface{}{"recovery_codes": codes})
}

// requireCurrentCode re-checks the second factor before sensitive changes.
func requireCurrentCode(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string) (*MFARecord, bool) {
	codeCheckMu.Lock()
	defer codeCheckMu.Unlock()
	var body struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &body); err != nil {
		jsonError(w, http.StatusBadRequest, "Bad request")
		return nil, false
	}
	record, err := LoadMFA(root, user)
	if err != nil || !record.Enrolled() {
		jsonError(w, http.StatusBadRequest, errNotEnrolledLabel)
		return nil, false
	}
	now := time.Now()
	if tooManyFailures(user, now) {
		jsonError(w, http.StatusTooManyRequests, errTooManyAttempts)
		return nil, false
	}
	apply, ok := verifySecondFactor(record, body.Code, now)
	if !ok {
		recordFailure(user, now)
		jsonError(w, http.StatusForbidden, errInvalidCode)
		return nil, false
	}
	updated, err := UpdateMFA(root, user, apply)
	if err != nil {
		jsonError(w, http.StatusForbidden, errInvalidCode)
		return nil, false
	}
	clearFailures(user)
	return updated, true
}

func disableTOTP(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string) {
	if _, ok := requireCurrentCode(w, r, root, user); !ok {
		return
	}
	if _, err := UpdateMFA(root, user, func(rec *MFARecord) error {
		rec.TOTPSecret = ""
		rec.PendingTOTPSecret = ""
		rec.RecoveryHashes = nil
		rec.Generation++
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not update two-factor settings.")
		return
	}
	audit(r.Context(), root, user, "mfa_disabled", ordereddict.NewDict())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func regenerateRecovery(w http.ResponseWriter, r *http.Request, root *config_proto.Config, user string) {
	if _, ok := requireCurrentCode(w, r, root, user); !ok {
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not create recovery codes.")
		return
	}
	if _, err := UpdateMFA(root, user, func(rec *MFARecord) error {
		rec.RecoveryHashes = hashes
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not save recovery codes.")
		return
	}
	audit(r.Context(), root, user, "mfa_recovery_regenerated", ordereddict.NewDict())
	writeJSON(w, http.StatusOK, map[string]interface{}{"recovery_codes": codes})
}

// Admins can see whether a user enrolled, and reset a user's second
// factor (for a lost phone). Requires SERVER_ADMIN on the root org.
func adminAction(w http.ResponseWriter, r *http.Request, root *config_proto.Config, admin, action string) {
	ok, err := services.CheckAccess(root, admin, acls.SERVER_ADMIN)
	if err != nil || !ok {
		jsonError(w, http.StatusForbidden, "Only server administrators can do this.")
		return
	}
	var target string
	if action == "user_status" {
		target = r.URL.Query().Get("username")
	} else {
		var body struct {
			Username string `json:"username"`
		}
		if err := readJSON(r, &body); err != nil {
			jsonError(w, http.StatusBadRequest, "Bad request")
			return
		}
		target = body.Username
	}
	if target == "" || len(target) > 256 {
		jsonError(w, http.StatusBadRequest, "username is required")
		return
	}

	// Always work on the stored user name, so the record path and the
	// cache key are the same ones the login check uses.
	user_record, err := services.GetUserManager().GetUser(r.Context(), admin, target)
	if err != nil || user_record == nil || user_record.Name == "" {
		jsonError(w, http.StatusNotFound, "No such user.")
		return
	}
	target = user_record.Name

	if action == "user_status" {
		record, err := LoadMFA(root, target)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Could not read two-factor status.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"username": target, "enrolled": record.Enrolled()})
		return
	}

	if _, err := UpdateMFA(root, target, func(rec *MFARecord) error {
		rec.TOTPSecret = ""
		rec.PendingTOTPSecret = ""
		rec.RecoveryHashes = nil
		rec.Generation++
		return nil
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Could not reset two-factor settings.")
		return
	}
	audit(r.Context(), root, admin, "mfa_admin_reset", ordereddict.NewDict().Set("username", target))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

var mfaPageTemplate = template.Must(template.New("mfa").Parse(mfaPageHTML))

func mfaPage(config_obj *config_proto.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		_ = mfaPageTemplate.Execute(w, map[string]string{
			"CsrfToken": csrf.Token(r),
			"BasePath":  api_utils.GetBasePath(config_obj),
			"User":      userFromContext(r),
		})
	}
}
