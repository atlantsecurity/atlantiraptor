package authenticators

import "testing"

func TestPolicyRequires(t *testing.T) {
	userIs := func(roles, groups []string) func() ([]string, []string) {
		return func() ([]string, []string) { return roles, groups }
	}
	cases := []struct {
		name   string
		policy MFAPolicy
		roles  []string
		groups []string
		want   bool
	}{
		{"default all", defaultMFAPolicy, nil, nil, true},
		{"off", MFAPolicy{Mode: MFAModeOff}, []string{"administrator"}, nil, false},
		{"selected by role match", MFAPolicy{Mode: MFAModeSelected, Roles: []string{"administrator"}}, []string{"reader", "administrator"}, nil, true},
		{"selected by role no match", MFAPolicy{Mode: MFAModeSelected, Roles: []string{"administrator"}}, []string{"reader"}, nil, false},
		{"selected by group match case-insensitive", MFAPolicy{Mode: MFAModeSelected, Groups: []string{"SOC"}}, nil, []string{"soc"}, true},
		{"selected nothing listed", MFAPolicy{Mode: MFAModeSelected}, []string{"administrator"}, []string{"soc"}, false},
		{"unknown mode fails safe", MFAPolicy{Mode: "weird"}, nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := policyRequires(c.policy, userIs(c.roles, c.groups)); got != c.want {
				t.Errorf("policyRequires = %v, want %v", got, c.want)
			}
		})
	}

	for _, bad := range []MFAPolicy{{Mode: "sometimes"}, {Mode: MFAModeSelected, Roles: []string{"god"}}, {Mode: MFAModeSelected, Groups: []string{""}}} {
		p := bad
		if err := validateMFAPolicy(&p); err == nil {
			t.Errorf("validateMFAPolicy(%+v) accepted an invalid policy", bad)
		}
	}
}
