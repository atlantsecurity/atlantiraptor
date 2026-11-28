package orgs

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	"www.velocidex.com/golang/velociraptor/datastore"
	"www.velocidex.com/golang/velociraptor/paths"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const MaxOrgNameLength = 100

// ValidateOrgName trims the name and checks it is usable as an org's
// display name.
func ValidateOrgName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("An organization name is required.")
	}
	if utf8.RuneCountInString(name) > MaxOrgNameLength {
		return "", fmt.Errorf("Organization names are at most %d characters.", MaxOrgNameLength)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("Organization names can not contain control characters.")
		}
	}
	return name, nil
}

// RenameOrg changes an org's display name. The org ID and nonce (which
// ties deployed clients to the org) stay the same, so nothing on the
// endpoints changes.
func (self *OrgManager) RenameOrg(org_id, name string) (*api_proto.OrgRecord, error) {
	name, err := ValidateOrgName(name)
	if err != nil {
		return nil, err
	}

	org_id = utils.NormalizedOrgId(org_id)
	if utils.IsRootOrg(org_id) {
		return nil, errors.New("The root organization can not be renamed.")
	}

	self.mu.Lock()
	org_ctx, pres := self.orgs[org_id]
	self.mu.Unlock()
	if !pres {
		return nil, services.OrgNotFoundError
	}
	if org_ctx.record.Redirected || org_ctx.redirect != nil {
		return nil, errors.New("Redirected organizations are renamed in the server config.")
	}

	record := proto.Clone(org_ctx.record).(*api_proto.OrgRecord)
	record.Name = name

	db, err := datastore.GetDB(self.config_obj)
	if err != nil {
		return nil, err
	}
	err = db.SetSubjectWithCompletion(self.config_obj,
		paths.NewOrgPathManager(org_id).Path(), record, utils.SyncCompleter)
	if err != nil {
		return nil, err
	}

	self.mu.Lock()
	org_ctx.record = record
	org_ctx.config_obj.OrgName = name
	self.mu.Unlock()

	return proto.Clone(record).(*api_proto.OrgRecord), nil
}
