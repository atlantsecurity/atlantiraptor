package acl_manager

import (
	"reflect"
	"testing"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestValidateGroups(t *testing.T) {
	root := &config_proto.Config{OrgId: ""}
	sub := &config_proto.Config{OrgId: "O123"}

	cases := []struct {
		name    string
		cfg     *config_proto.Config
		groups  []Group
		wantErr bool
	}{
		{"valid", root, []Group{{Name: "SOC Tier 1", Roles: []string{"hunter"}, Members: []string{"bob", "alice", "bob"}}}, false},
		{"unknown role", root, []Group{{Name: "x", Roles: []string{"superuser"}}}, true},
		{"bad name", root, []Group{{Name: "../etc", Roles: []string{"reader"}}}, true},
		{"duplicate name", root, []Group{{Name: "A", Roles: nil}, {Name: "a", Roles: nil}}, true},
		{"org_admin in root", root, []Group{{Name: "admins", Roles: []string{"org_admin"}}}, false},
		{"org_admin outside root", sub, []Group{{Name: "admins", Roles: []string{"org_admin"}}}, true},
		{"empty member", root, []Group{{Name: "x", Members: []string{""}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ValidateGroups(c.cfg, c.groups)
			if (err != nil) != c.wantErr {
				t.Errorf("err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}

	out, err := ValidateGroups(root, []Group{{Name: "SOC", Roles: []string{"hunter", "hunter"}, Members: []string{"bob", "alice", "bob"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out[0].Members, []string{"alice", "bob"}) || !reflect.DeepEqual(out[0].Roles, []string{"hunter"}) {
		t.Errorf("not normalised: %+v", out[0])
	}
}

func TestGroupRoles(t *testing.T) {
	groups := []Group{
		{Name: "hunters", Roles: []string{"hunter"}, Members: []string{"Alice", "bob"}},
		{Name: "responders", Roles: []string{"responder", "hunter"}, Members: []string{"alice"}},
		{Name: "readers", Roles: []string{"reader"}, Members: []string{"carol"}},
	}
	if got := groupRoles(groups, "alice"); !reflect.DeepEqual(got, []string{"hunter", "responder"}) {
		t.Errorf("alice roles = %v", got)
	}
	if got := groupRoles(groups, "bob"); !reflect.DeepEqual(got, []string{"hunter"}) {
		t.Errorf("bob roles = %v", got)
	}
	if got := groupRoles(groups, "mallory"); len(got) != 0 {
		t.Errorf("non-member got roles %v", got)
	}
}
