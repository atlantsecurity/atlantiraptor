package acls

import (
	"testing"

	acl_proto "www.velocidex.com/golang/velociraptor/acls/proto"
)

// Hunter and Responder must differ exactly by the endpoint-changing
// permissions that response artifacts require.
func TestHunterAndResponderRoles(t *testing.T) {
	cases := []struct {
		role            string
		wantResponse    bool
		wantCollectHunt bool
	}{
		{"hunter", false, true},
		{"responder", true, true},
		{"reader", false, false},
	}

	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			if !ValidateRole(c.role) {
				t.Fatalf("role %q is not valid", c.role)
			}
			policy := &acl_proto.ApiClientACL{}
			if err := GetRolePermissions(nil, []string{c.role}, policy); err != nil {
				t.Fatalf("GetRolePermissions(%q): %v", c.role, err)
			}

			canRespond := policy.Execve && policy.FilesystemWrite && policy.Network
			if canRespond != c.wantResponse {
				t.Errorf("%s: response permissions = %v, want %v", c.role, canRespond, c.wantResponse)
			}
			if policy.Execve != c.wantResponse || policy.FilesystemWrite != c.wantResponse || policy.Network != c.wantResponse {
				t.Errorf("%s: partial response permissions: execve=%v fs_write=%v network=%v",
					c.role, policy.Execve, policy.FilesystemWrite, policy.Network)
			}
			if (policy.CollectClient && policy.StartHunt) != c.wantCollectHunt {
				t.Errorf("%s: collect+hunt = %v, want %v", c.role, policy.CollectClient && policy.StartHunt, c.wantCollectHunt)
			}
			if policy.ServerAdmin || policy.ArtifactWriter || policy.AnyQuery {
				t.Errorf("%s: must not grant admin, artifact writing or arbitrary queries", c.role)
			}
		})
	}
}
