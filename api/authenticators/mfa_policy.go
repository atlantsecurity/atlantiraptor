package authenticators

// Who must use two-factor sign in. Stored as one JSON document in the
// root org file store. When no policy has been saved, 2FA is required
// for everyone: users who have not enrolled are taken through
// enrolment at their next sign in (see mfaGate), so nobody is locked
// out. ATLANTIRAPTOR_DISABLE_MFA=1 overrides everything.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/acl_manager"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	MFAModeAll      = "all"
	MFAModeSelected = "selected"
	MFAModeOff      = "off"
)

type MFAPolicy struct {
	Mode    string   `json:"mode"`
	Roles   []string `json:"roles,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Updated int64    `json:"updated,omitempty"`
}

var defaultMFAPolicy = MFAPolicy{Mode: MFAModeAll}

var (
	policyMu      sync.Mutex
	policyCache   *MFAPolicy
	policyFetched time.Time
)

func mfaPolicyPath() api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_mfa_policy").
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

// LoadMFAPolicy returns the saved policy, or the default (required for
// everyone) when none was saved.
func LoadMFAPolicy(root *config_proto.Config) (MFAPolicy, error) {
	policyMu.Lock()
	defer policyMu.Unlock()
	if policyCache != nil && time.Since(policyFetched) < mfaCacheTTL {
		return *policyCache, nil
	}

	fs := file_store.GetFileStore(root)
	if fs == nil {
		return defaultMFAPolicy, errors.New("file store unavailable")
	}
	if _, err := fs.StatFile(mfaPolicyPath()); err != nil {
		if isNotExist(err) {
			p := defaultMFAPolicy
			policyCache, policyFetched = &p, time.Now()
			return p, nil
		}
		return defaultMFAPolicy, fmt.Errorf("stat 2FA policy: %w", err)
	}
	reader, err := fs.ReadFile(mfaPolicyPath())
	if err != nil {
		return defaultMFAPolicy, fmt.Errorf("open 2FA policy: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		return defaultMFAPolicy, fmt.Errorf("read 2FA policy: %w", err)
	}
	p := MFAPolicy{}
	if err := json.Unmarshal(data, &p); err != nil {
		return defaultMFAPolicy, fmt.Errorf("parse 2FA policy: %w", err)
	}
	if err := validateMFAPolicy(&p); err != nil {
		return defaultMFAPolicy, err
	}
	policyCache, policyFetched = &p, time.Now()
	return p, nil
}

func validateMFAPolicy(p *MFAPolicy) error {
	switch p.Mode {
	case MFAModeAll, MFAModeSelected, MFAModeOff:
	default:
		return fmt.Errorf("unknown 2FA mode %q", p.Mode)
	}
	for _, r := range p.Roles {
		if !acls.ValidateRole(r) {
			return fmt.Errorf("unknown role %q", r)
		}
	}
	if len(p.Groups) > 200 {
		return fmt.Errorf("too many groups")
	}
	for _, g := range p.Groups {
		if g == "" || len(g) > 64 {
			return fmt.Errorf("invalid group name %q", g)
		}
	}
	return nil
}

func SaveMFAPolicy(root *config_proto.Config, p MFAPolicy) (MFAPolicy, error) {
	if err := validateMFAPolicy(&p); err != nil {
		return MFAPolicy{}, err
	}
	p.Updated = time.Now().Unix()
	data, err := json.Marshal(p)
	if err != nil {
		return MFAPolicy{}, err
	}
	fs := file_store.GetFileStore(root)
	if fs == nil {
		return MFAPolicy{}, errors.New("file store unavailable")
	}

	policyMu.Lock()
	defer policyMu.Unlock()
	writer, err := fs.WriteFile(mfaPolicyPath())
	if err != nil {
		return MFAPolicy{}, fmt.Errorf("open 2FA policy for writing: %w", err)
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return MFAPolicy{}, err
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return MFAPolicy{}, err
	}
	if err := writer.Close(); err != nil {
		return MFAPolicy{}, err
	}
	policyCache, policyFetched = &p, time.Now()
	return p, nil
}

// mfaRequiredFor decides whether a user must use 2FA. Roles and groups
// are collected across every org the user belongs to (and the root
// org). Anything that can't be read means 2FA is required: enrolment is
// always possible, so failing closed never locks anyone out.
func mfaRequiredFor(root *config_proto.Config, username string) bool {
	p, err := LoadMFAPolicy(root)
	if err != nil {
		return true
	}
	if p.Mode != MFAModeSelected {
		return policyRequires(p, nil)
	}

	roles, groups, err := rolesAndGroupsAllOrgs(root, username)
	if err != nil {
		return true
	}
	return policyRequires(p, func() ([]string, []string) { return roles, groups })
}

func rolesAndGroupsAllOrgs(root *config_proto.Config, username string) ([]string, []string, error) {
	configs := []*config_proto.Config{root}

	user_record, err := services.GetUserManager().GetUser(context.Background(), username, username)
	if err != nil {
		return nil, nil, err
	}
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return nil, nil, err
	}
	for _, org := range user_record.Orgs {
		if utils.IsRootOrg(org.Id) {
			continue
		}
		org_config, err := org_manager.GetOrgConfig(org.Id)
		if err != nil {
			return nil, nil, err
		}
		configs = append(configs, org_config)
	}

	roles, groups := []string{}, []string{}
	for _, cfg := range configs {
		r, g, err := acl_manager.UserRolesAndGroups(cfg, username)
		if err != nil {
			return nil, nil, err
		}
		for _, x := range r {
			if !utils.InString(roles, x) {
				roles = append(roles, x)
			}
		}
		groups = append(groups, g...)
	}
	return roles, groups, nil
}

func policyRequires(p MFAPolicy, rolesAndGroups func() ([]string, []string)) bool {
	switch p.Mode {
	case MFAModeOff:
		return false
	case MFAModeSelected:
		roles, groups := rolesAndGroups()
		for _, r := range p.Roles {
			if utils.InString(roles, r) {
				return true
			}
		}
		for _, g := range p.Groups {
			for _, have := range groups {
				if utils.ToLower(g) == utils.ToLower(have) {
					return true
				}
			}
		}
		return false
	default:
		return true
	}
}
