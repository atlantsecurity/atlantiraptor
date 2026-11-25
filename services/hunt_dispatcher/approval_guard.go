package hunt_dispatcher

// Two-person approval, enforced by the server for every way a hunt can
// be changed (console, REST API, VQL hunt_update). A hunt tagged
// approval:pending is a live response action waiting for a second
// person:
//
//   - It can't be started while it is still pending.
//   - The pending tag can only be removed by recording a decision for the
//     user making the change, in the same change: approval:approved-by:<user>
//     together with RUNNING, or approval:rejected-by:<user> (not RUNNING).
//   - Approval is refused for the requester (the hunt's creator) and, when
//     the request came from an API key, for the person who created that
//     key. The approver must also hold every permission the request's
//     artifacts require, so a hunter can't approve a kill.
//   - A rejected hunt can never be started again, and decision tags can't
//     be added or removed outside a decision.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"www.velocidex.com/golang/velociraptor/acls"
	api_proto "www.velocidex.com/golang/velociraptor/api/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	fs_api "www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	approvalPendingTag    = "approval:pending"
	approvalApprovedByTag = "approval:approved-by:"
	approvalRejectedByTag = "approval:rejected-by:"
	apiKeyPrincipalPrefix = "api-"
)

var ErrApproval = errors.New("approval rule")

func isDecisionTag(t string) bool {
	return strings.HasPrefix(t, approvalApprovedByTag) || strings.HasPrefix(t, approvalRejectedByTag)
}

func hasTagWithPrefix(tags []string, prefix string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

func decisionTags(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		if isDecisionTag(t) {
			out = append(out, t)
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !utils.InString(b, x) {
			return false
		}
	}
	return true
}

// checkApprovalMutation returns an error when the mutation would break
// the approval rules for this hunt.
func checkApprovalMutation(ctx context.Context, config_obj *config_proto.Config,
	hunt *api_proto.Hunt, mutation *api_proto.HuntMutation) error {

	if hunt == nil {
		return nil
	}
	pending := utils.InString(hunt.Tags, approvalPendingTag)
	rejected := hasTagWithPrefix(hunt.Tags, approvalRejectedByTag)
	newTags := hunt.Tags
	tagsChange := len(mutation.Tags) > 0
	if tagsChange {
		newTags = mutation.Tags
	}

	if rejected && mutation.State == api_proto.Hunt_RUNNING {
		return fmt.Errorf("%w: a rejected request can't be started", ErrApproval)
	}

	removesPending := pending && tagsChange && !utils.InString(newTags, approvalPendingTag)
	if !removesPending {
		if pending && mutation.State == api_proto.Hunt_RUNNING {
			return fmt.Errorf("%w: this request is waiting for approval", ErrApproval)
		}
		// Decision tags only change as part of a decision.
		if tagsChange && !sameSet(decisionTags(hunt.Tags), decisionTags(newTags)) {
			return fmt.Errorf("%w: approval decisions can only be recorded by approving or rejecting", ErrApproval)
		}
		return nil
	}

	// A decision: exactly one new decision tag, for the user making it.
	user := mutation.User
	added := []string{}
	for _, t := range decisionTags(newTags) {
		if !utils.InString(hunt.Tags, t) {
			added = append(added, t)
		}
	}
	for _, t := range decisionTags(hunt.Tags) {
		if !utils.InString(newTags, t) {
			return fmt.Errorf("%w: earlier decisions can't be removed", ErrApproval)
		}
	}
	if user == "" || len(added) != 1 {
		return fmt.Errorf("%w: a decision must name the user deciding", ErrApproval)
	}

	switch added[0] {
	case approvalRejectedByTag + user:
		if mutation.State == api_proto.Hunt_RUNNING {
			return fmt.Errorf("%w: a rejected request can't be started", ErrApproval)
		}
		return nil

	case approvalApprovedByTag + user:
		if mutation.State != api_proto.Hunt_RUNNING {
			return fmt.Errorf("%w: approval must start the hunt in the same change", ErrApproval)
		}
		return checkApprover(ctx, config_obj, hunt, user)
	}
	return fmt.Errorf("%w: the decision must be recorded for %v", ErrApproval, user)
}

func checkApprover(ctx context.Context, config_obj *config_proto.Config,
	hunt *api_proto.Hunt, user string) error {

	requesters := []string{hunt.Creator}
	if strings.HasPrefix(hunt.Creator, apiKeyPrincipalPrefix) {
		owner, err := apiKeyOwner(strings.TrimPrefix(hunt.Creator, apiKeyPrincipalPrefix))
		if err != nil {
			return fmt.Errorf("%w: can't tell who owns the requesting key", ErrApproval)
		}
		requesters = append(requesters, owner)
	}
	// An approving key counts as the person who created it.
	approvers := []string{user}
	if strings.HasPrefix(user, apiKeyPrincipalPrefix) {
		owner, err := apiKeyOwner(strings.TrimPrefix(user, apiKeyPrincipalPrefix))
		if err != nil {
			return fmt.Errorf("%w: can't tell who owns the approving key", ErrApproval)
		}
		approvers = append(approvers, owner)
	}
	for _, r := range requesters {
		for _, a := range approvers {
			if r != "" && utils.UsernamesEqual(r, a) {
				return fmt.Errorf("%w: the requester can't approve their own request", ErrApproval)
			}
		}
	}

	// The approver must be allowed to run what they approve.
	if ok, _ := services.CheckAccess(config_obj, user, acls.START_HUNT); !ok {
		return fmt.Errorf("%w: approving needs permission to start hunts", ErrApproval)
	}
	if hunt.StartRequest == nil {
		return nil
	}
	manager, err := services.GetRepositoryManager(config_obj)
	if err != nil {
		return err
	}
	repository, err := manager.GetGlobalRepository(config_obj)
	if err != nil {
		return err
	}
	for _, name := range hunt.StartRequest.Artifacts {
		artifact, ok := repository.Get(ctx, config_obj, name)
		if !ok || artifact == nil {
			return fmt.Errorf("%w: unknown artifact %v", ErrApproval, name)
		}
		for _, perm := range artifact.RequiredPermissions {
			if ok, _ := services.CheckAccess(config_obj, user, acls.GetPermission(perm)); !ok {
				return fmt.Errorf("%w: approving %v needs the %v permission", ErrApproval, name, perm)
			}
		}
	}
	return nil
}

// apiKeyOwner reads who created an API key from the key store (root org
// file store, config/atl_api_keys.json; see api/atlapi_keys.go).
func apiKeyOwner(id string) (string, error) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return "", err
	}
	root, err := org_manager.GetOrgConfig(services.ROOT_ORG_ID)
	if err != nil {
		return "", err
	}
	fs := file_store.GetFileStore(root)
	if fs == nil {
		return "", errors.New("file store unavailable")
	}
	reader, err := fs.ReadFile(path_specs.NewSafeFilestorePath("config", "atl_api_keys").
		SetType(fs_api.PATH_TYPE_FILESTORE_JSON))
	if err != nil {
		return "", err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 4<<20))
	if err != nil {
		return "", err
	}
	var doc struct {
		Keys []struct {
			ID        string `json:"id"`
			CreatedBy string `json:"created_by"`
		} `json:"keys"`
		Revoked []struct {
			ID        string `json:"id"`
			CreatedBy string `json:"created_by"`
		} `json:"revoked"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", err
	}
	for _, k := range append(doc.Keys, doc.Revoked...) {
		if k.ID == id {
			if k.CreatedBy == "" {
				return "", errors.New("key has no owner")
			}
			return k.CreatedBy, nil
		}
	}
	// Unknown key: refuse rather than guess.
	return "", errors.New("unknown API key")
}
