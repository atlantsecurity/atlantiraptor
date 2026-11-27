package authenticators

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	totpPeriod          = 30
	totpSkew            = 1 // accept the previous and next 30s step
	maxFailures         = 5
	failureWindow       = 5 * time.Minute
	recoveryCodeCount   = 8
	TOTPIssuer          = "Atlantiraptor"
	errTooManyAttempts  = "Too many attempts. Wait a few minutes and try again."
	errInvalidCode      = "That code is not valid."
	errNotEnrolledLabel = "Two-factor authentication is not enabled for this user."
)

// Per-user failure counter so codes can't be brute forced.
type failureState struct {
	count int
	start time.Time
}

var (
	failMu   sync.Mutex
	failures = map[string]*failureState{}
)

func tooManyFailures(username string, now time.Time) bool {
	failMu.Lock()
	defer failMu.Unlock()
	f := failures[utils.ToLower(username)]
	if f == nil || now.Sub(f.start) > failureWindow {
		return false
	}
	return f.count >= maxFailures
}

func recordFailure(username string, now time.Time) {
	failMu.Lock()
	defer failMu.Unlock()
	key := utils.ToLower(username)
	f := failures[key]
	if f == nil || now.Sub(f.start) > failureWindow {
		failures[key] = &failureState{count: 1, start: now}
		return
	}
	f.count++
}

func clearFailures(username string) {
	failMu.Lock()
	defer failMu.Unlock()
	delete(failures, utils.ToLower(username))
}

// totpStep returns the time step that code matches for secret, or -1.
func totpStep(secret, code string, now time.Time) int64 {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return -1
	}
	current := now.Unix() / totpPeriod
	for delta := int64(-totpSkew); delta <= totpSkew; delta++ {
		step := current + delta
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(step*totpPeriod, 0),
			totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			return -1
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step
		}
	}
	return -1
}

func hashRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte("atlantiraptor-recovery-v1\x00" + normalized))
	return hex.EncodeToString(sum[:])
}

func newRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)[:10]
		code := raw[:5] + "-" + raw[5:]
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// verifySecondFactor checks a TOTP code or a recovery code against the
// record and returns the change to persist (replay step, consumed code).
func verifySecondFactor(record *MFARecord, code string, now time.Time) (func(r *MFARecord) error, bool) {
	if !record.Enrolled() {
		return nil, false
	}
	if step := totpStep(record.TOTPSecret, code, now); step >= 0 {
		if step <= record.TOTPLastStep {
			return nil, false // replayed code
		}
		return func(r *MFARecord) error {
			if step <= r.TOTPLastStep {
				return fmt.Errorf("code already used")
			}
			r.TOTPLastStep = step
			return nil
		}, true
	}

	hash := hashRecoveryCode(code)
	for _, h := range record.RecoveryHashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(hash)) == 1 {
			return func(r *MFARecord) error {
				kept := r.RecoveryHashes[:0]
				found := false
				for _, existing := range r.RecoveryHashes {
					if existing == hash && !found {
						found = true
						continue
					}
					kept = append(kept, existing)
				}
				if !found {
					return fmt.Errorf("recovery code already used")
				}
				r.RecoveryHashes = kept
				return nil
			}, true
		}
	}
	return nil, false
}

func newTOTPKey(username string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: username,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		SecretSize:  20,
	})
}
