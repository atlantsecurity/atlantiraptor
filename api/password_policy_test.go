package api

import "testing"

func TestCheckPasswordPolicy(t *testing.T) {
	cases := []struct {
		name, user, password string
		want                 error
	}{
		{"strong", "alice", "Correct-Horse-9", nil},
		{"three classes no symbol", "alice", "CorrectHorse99", nil},
		{"too short", "alice", "Sh0rt!x", errPasswordLength},
		{"one class", "alice", "alllowercaseletters", errPasswordClasses},
		{"two classes", "alice", "lowercaseand12345", errPasswordClasses},
		{"contains user", "alice", "Alice-Secret-2026", errPasswordUser},
		{"common padded short", "bob", "Password123!", errPasswordCommon},
		{"common inside long passphrase is fine", "bob", "My-Password-Is-Long-And-Odd-77", nil},
		{"too long", "bob", string(make([]rune, 300)), errPasswordTooLong},
		{"unicode counts runes", "bob", "Пароль-Длинный-1", nil},
		{"passphrase four words lower case", "bob", "correct horse battery staple", nil},
		{"passphrase with dashes", "bob", "orange-river-quiet-lamp", nil},
		{"three words is not a passphrase", "bob", "orange river quietlamp", errPasswordClasses},
		{"four short words under 20 chars", "bob", "red cat big sun", errPasswordClasses},
		{"four words but 19 chars", "bob", "abcd efgh ijkl mnop", errPasswordClasses},
		{"repeated word is not a passphrase", "bob", "banana banana banana banana", errPasswordClasses},
		{"passphrase containing user name", "alice", "alice likes green tea", errPasswordUser},
		{"passphrase built on common password", "bob", "password one two three", errPasswordCommon},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckPasswordPolicy(c.user, c.password)
			if got != c.want {
				t.Errorf("CheckPasswordPolicy(%q, %q) = %v, want %v", c.user, c.password, got, c.want)
			}
		})
	}
}
