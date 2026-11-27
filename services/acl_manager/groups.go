package acl_manager

// Groups give roles to many users at once. Each org has its own list of
// groups, stored as one JSON document in that org's file store. The ACL
// manager merges the roles of every group a user belongs to into the
// user's effective policy, so group roles are enforced by every
// permission check exactly like roles set on the user.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"www.velocidex.com/golang/velociraptor/acls"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	groupsCacheTTL   = 10 * time.Second
	MaxGroups        = 200
	MaxGroupMembers  = 1000
	maxGroupsDocSize = 4 << 20
)

var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$`)

type Group struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Roles       []string `json:"roles"`
	Members     []string `json:"members"`
}

type groupsDoc struct {
	Groups  []Group `json:"groups"`
	Updated int64   `json:"updated"`
}

type groupsCacheEntry struct {
	doc     *groupsDoc
	fetched time.Time
}

var (
	groupsMu    sync.Mutex
	groupsCache = map[string]groupsCacheEntry{}
)

func groupsPath() api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_groups").
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func orgKey(config_obj *config_proto.Config) string {
	if config_obj == nil {
		return ""
	}
	return config_obj.OrgId
}

func readGroups(config_obj *config_proto.Config) (*groupsDoc, error) {
	fs := file_store.GetFileStore(config_obj)
	if fs == nil {
		return &groupsDoc{}, nil
	}
	if _, err := fs.StatFile(groupsPath()); err != nil {
		if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
			return &groupsDoc{}, nil
		}
		return nil, fmt.Errorf("stat groups: %w", err)
	}
	reader, err := fs.ReadFile(groupsPath())
	if err != nil {
		return nil, fmt.Errorf("open groups: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxGroupsDocSize))
	if err != nil {
		return nil, fmt.Errorf("read groups: %w", err)
	}
	doc := &groupsDoc{}
	if len(data) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("parse groups: %w", err)
	}
	return doc, nil
}

// GetGroups returns the org's groups (cached briefly).
func GetGroups(config_obj *config_proto.Config) ([]Group, error) {
	key := orgKey(config_obj)
	groupsMu.Lock()
	entry, ok := groupsCache[key]
	groupsMu.Unlock()
	if ok && time.Since(entry.fetched) < groupsCacheTTL {
		return entry.doc.Groups, nil
	}
	doc, err := readGroups(config_obj)
	if err != nil {
		return nil, err
	}
	groupsMu.Lock()
	groupsCache[key] = groupsCacheEntry{doc: doc, fetched: time.Now()}
	groupsMu.Unlock()
	return doc.Groups, nil
}

// ValidateGroups normalises and checks a full list of groups before it
// is stored: names, known roles only, org_admin only in the root org,
// and size limits.
func ValidateGroups(config_obj *config_proto.Config, groups []Group) ([]Group, error) {
	if len(groups) > MaxGroups {
		return nil, fmt.Errorf("at most %d groups", MaxGroups)
	}
	seen := map[string]bool{}
	out := make([]Group, 0, len(groups))
	for _, g := range groups {
		if !groupNameRe.MatchString(g.Name) {
			return nil, fmt.Errorf("invalid group name %q", g.Name)
		}
		lower := utils.ToLower(g.Name)
		if seen[lower] {
			return nil, fmt.Errorf("duplicate group name %q", g.Name)
		}
		seen[lower] = true

		roles := []string{}
		for _, role := range g.Roles {
			if !acls.ValidateRole(role) {
				return nil, fmt.Errorf("group %q: unknown role %q", g.Name, role)
			}
			if role == "org_admin" && !utils.IsRootOrg(orgKey(config_obj)) {
				return nil, fmt.Errorf("group %q: org_admin can only be granted in the root org", g.Name)
			}
			if !utils.InString(roles, role) {
				roles = append(roles, role)
			}
		}

		if len(g.Members) > MaxGroupMembers {
			return nil, fmt.Errorf("group %q: at most %d members", g.Name, MaxGroupMembers)
		}
		// User names compare case-insensitively, as in the lookup.
		members := []string{}
		seenMember := map[string]bool{}
		for _, m := range g.Members {
			if m == "" || len(m) > 256 {
				return nil, fmt.Errorf("group %q: invalid member name", g.Name)
			}
			if !seenMember[utils.ToLower(m)] {
				seenMember[utils.ToLower(m)] = true
				members = append(members, m)
			}
		}
		sort.Strings(members)

		if len(g.Description) > 500 {
			g.Description = g.Description[:500]
		}
		out = append(out, Group{Name: g.Name, Description: g.Description, Roles: roles, Members: members})
	}
	return out, nil
}

var setGroupsMu sync.Mutex

// SetGroups validates and stores the org's full list of groups.
func SetGroups(config_obj *config_proto.Config, groups []Group) ([]Group, error) {
	setGroupsMu.Lock()
	defer setGroupsMu.Unlock()

	valid, err := ValidateGroups(config_obj, groups)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(&groupsDoc{Groups: valid, Updated: time.Now().Unix()})
	if err != nil {
		return nil, err
	}
	fs := file_store.GetFileStore(config_obj)
	if fs == nil {
		return nil, errors.New("file store unavailable")
	}
	writer, err := fs.WriteFile(groupsPath())
	if err != nil {
		return nil, fmt.Errorf("open groups for writing: %w", err)
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return nil, fmt.Errorf("truncate groups: %w", err)
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, fmt.Errorf("write groups: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close groups: %w", err)
	}
	groupsMu.Lock()
	groupsCache[orgKey(config_obj)] = groupsCacheEntry{doc: &groupsDoc{Groups: valid}, fetched: time.Now()}
	groupsMu.Unlock()
	return valid, nil
}

// UserRolesAndGroups returns the roles a user holds in this org (their
// own plus those from groups) and the names of the groups they are in.
func UserRolesAndGroups(config_obj *config_proto.Config, principal string) ([]string, []string, error) {
	roles := []string{}
	policy, err := services.GetPolicy(config_obj, principal)
	if err == nil && policy != nil {
		roles = append(roles, policy.Roles...)
	} else if err != nil && !errors.Is(err, utils.NotFoundError) && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	names := []string{}
	groups, err := GetGroups(config_obj)
	if err != nil {
		return nil, nil, err
	}
	{
		for _, role := range groupRoles(groups, principal) {
			if !utils.InString(roles, role) {
				roles = append(roles, role)
			}
		}
		for _, g := range groups {
			for _, m := range g.Members {
				if utils.UsernamesEqual(m, principal) {
					names = append(names, g.Name)
					break
				}
			}
		}
	}
	return roles, names, nil
}

// groupRoles returns the roles a principal gets through groups.
func groupRoles(groups []Group, principal string) []string {
	roles := []string{}
	for _, g := range groups {
		for _, m := range g.Members {
			if utils.UsernamesEqual(m, principal) {
				for _, role := range g.Roles {
					if !utils.InString(roles, role) {
						roles = append(roles, role)
					}
				}
				break
			}
		}
	}
	return roles
}
