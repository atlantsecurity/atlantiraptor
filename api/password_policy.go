package api

import (
	"errors"
	"strings"
	"unicode"

	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	PasswordMinLength = 12
	PasswordMaxLength = 256
)

// A short list of passwords that pass the character rules but are
// guessed first by every attacker.
var commonPasswords = []string{
	"password", "passw0rd", "letmein", "welcome", "qwerty", "admin",
	"administrator", "changeme", "velociraptor", "atlantiraptor",
	"123456", "iloveyou", "monkey", "dragon", "trustno1",
}

var (
	errPasswordLength  = errors.New("Password must be at least 12 characters long")
	errPasswordTooLong = errors.New("Password must be at most 256 characters long")
	errPasswordClasses = errors.New("Use a passphrase of four or more words (20+ characters), or mix at least three of: lower case, upper case, digits, symbols")
	errPasswordUser    = errors.New("Password must not contain the user name")
	errPasswordCommon  = errors.New("Password is too common")
)

const (
	PassphraseMinWords  = 4
	PassphraseMinLength = 20
	passphraseWordMin   = 2
)

// IsPassphrase reports whether a password is a passphrase: at least four
// words (separated by spaces, dashes, dots, underscores or commas), each
// at least two letters or digits, and at least 20 characters overall.
// Words must not all be the same.
func IsPassphrase(password string) bool {
	if len([]rune(password)) < PassphraseMinLength {
		return false
	}
	words := strings.FieldsFunc(password, func(r rune) bool {
		return unicode.IsSpace(r) || r == '-' || r == '.' || r == '_' || r == ','
	})
	distinct := map[string]bool{}
	count := 0
	for _, w := range words {
		if len([]rune(w)) >= passphraseWordMin {
			count++
			distinct[strings.ToLower(w)] = true
		}
	}
	return count >= PassphraseMinWords && len(distinct) >= 2
}

// CheckPasswordPolicy enforces the server password policy for
// passwords set through the API (the console's change and reset
// password actions).
func CheckPasswordPolicy(username, password string) error {
	length := len([]rune(password))
	if length < PasswordMinLength {
		return errPasswordLength
	}
	if length > PasswordMaxLength {
		return errPasswordTooLong
	}

	var lower, upper, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	// Passphrases (four or more words, 20+ characters) are accepted
	// without mixing character types: their length is their strength.
	if classes < 3 && !IsPassphrase(password) {
		return errPasswordClasses
	}

	lowered := strings.ToLower(password)
	if username != "" && len(username) >= 3 &&
		strings.Contains(lowered, strings.ToLower(username)) {
		return errPasswordUser
	}

	for _, common := range commonPasswords {
		if strings.Contains(lowered, common) && length < len(common)+6 {
			return errPasswordCommon
		}
	}

	// A passphrase must not be built on a common password either.
	if classes < 3 {
		for _, w := range strings.FieldsFunc(lowered, func(r rune) bool {
			return unicode.IsSpace(r) || r == '-' || r == '.' || r == '_' || r == ','
		}) {
			if utils.InString(commonPasswords, w) {
				return errPasswordCommon
			}
		}
	}
	return nil
}
