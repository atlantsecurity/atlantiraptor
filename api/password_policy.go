package api

import (
	"errors"
	"strings"
	"unicode"
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
	errPasswordClasses = errors.New("Password must mix at least three of: lower case, upper case, digits, symbols")
	errPasswordUser    = errors.New("Password must not contain the user name")
	errPasswordCommon  = errors.New("Password is too common")
)

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
	if classes < 3 {
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
	return nil
}
