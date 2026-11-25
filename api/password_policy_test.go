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
