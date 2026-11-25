package authenticators

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func testConfig(key string) *config_proto.Config {
	return &config_proto.Config{Frontend: &config_proto.FrontendConfig{PrivateKey: key}}
}

func TestMFACookie(t *testing.T) {
	cfg := testConfig("server-key")
	now := time.Unix(1_800_000_000, 0)
	good := NewMFACookieValue(cfg, "alice", 3, now)

	cases := []struct {
		name  string
		cfg   *config_proto.Config
		value string
		user  string
		gen   int64
		at    time.Time
		ok    bool
	}{
		{"valid", cfg, good, "alice", 3, now, true},
		{"username case-insensitive", cfg, good, "ALICE", 3, now, true},
		{"other user", cfg, good, "bob", 3, now, false},
		{"revoked generation", cfg, good, "alice", 4, now, false},
		{"expired", cfg, good, "alice", 3, now.Add(MFASessionTTL + time.Second), false},
		{"other server key", testConfig("different"), good, "alice", 3, now, false},
		{"tampered payload", cfg, "Ym9i" + good[len("YWxpY2U"):], "bob", 3, now, false},
		{"truncated", cfg, good[:len(good)-2], "alice", 3, now, false},
		{"garbage", cfg, "not-a-cookie", "alice", 3, now, false},
		{"empty server key never verifies", testConfig(""), NewMFACookieValue(testConfig(""), "alice", 3, now), "alice", 3, now, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyMFACookieValue(c.cfg, c.value, c.user, c.gen, c.at)
			if (err == nil) != c.ok {
				t.Errorf("VerifyMFACookieValue ok=%v, want %v (err=%v)", err == nil, c.ok, err)
			}
		})
	}
}

func TestSecondFactor(t *testing.T) {
	key, err := newTOTPKey("alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	code, err := totp.GenerateCodeCustom(key.Secret(), now,
		totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	record := &MFARecord{TOTPSecret: key.Secret(), RecoveryHashes: hashes}

	// A valid TOTP code is accepted once; replaying it is refused.
	apply, ok := verifySecondFactor(record, code, now)
	if !ok {
		t.Fatal("valid code refused")
	}
	if err := apply(record); err != nil {
		t.Fatal(err)
	}
	if _, ok := verifySecondFactor(record, code, now); ok {
		t.Error("replayed code accepted")
	}

	// Wrong codes and codes outside the skew window are refused.
	if _, ok := verifySecondFactor(record, "000000", now); ok {
		t.Error("wrong code accepted")
	}
	old, _ := totp.GenerateCodeCustom(key.Secret(), now.Add(-5*time.Minute),
		totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if _, ok := verifySecondFactor(&MFARecord{TOTPSecret: key.Secret()}, old, now); ok {
		t.Error("stale code accepted")
	}

	// A recovery code works once, with or without the dash.
	apply, ok = verifySecondFactor(record, codes[0], now)
	if !ok {
		t.Fatal("recovery code refused")
	}
	if err := apply(record); err != nil {
		t.Fatal(err)
	}
	if len(record.RecoveryHashes) != recoveryCodeCount-1 {
		t.Errorf("recovery code not consumed: %d left", len(record.RecoveryHashes))
	}
	if _, ok := verifySecondFactor(record, codes[0], now); ok {
		t.Error("recovery code reused")
	}
	undashed := codes[1][:5] + codes[1][6:]
	if _, ok := verifySecondFactor(record, undashed, now); !ok {
		t.Error("recovery code without dash refused")
	}

	// Without enrolment nothing is accepted.
	if _, ok := verifySecondFactor(&MFARecord{}, code, now); ok {
		t.Error("code accepted for a user who is not enrolled")
	}
}

func TestFailureLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	user := "limit-test-user"
	clearFailures(user)
	for i := 0; i < maxFailures; i++ {
		if tooManyFailures(user, now) {
			t.Fatalf("locked out after %d failures", i)
		}
		recordFailure(user, now)
	}
	if !tooManyFailures(user, now) {
		t.Error("not locked out after max failures")
	}
	if tooManyFailures(user, now.Add(failureWindow+time.Second)) {
		t.Error("lockout did not expire")
	}
}
