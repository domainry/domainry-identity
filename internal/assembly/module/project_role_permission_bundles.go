package moduleassembly

import (
	"context"
	"reflect"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// PublishProjectRolePermissionBundle persists a source-owned, fixed permission
// bundle without routing it through browser role authoring. This is the only
// supported path for bundled and internal grants owned by an embedding
// product; direct administrator selections remain guarded by the HTTP API.
func (binding *moduleBinding) PublishProjectRolePermissionBundle(ctx context.Context, request identitysdk.ProjectRolePermissionBundleRequest) (identitysdk.ProjectRolePermissionBundleReceipt, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Metadata == nil || binding.runtime.PermissionCatalog == nil {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.project_role_permission_bundle_unavailable"}
	}
	if err := request.ValidateContract(); err != nil {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, err
	}
	if request.Application != binding.application {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassForbidden, Code: "identity.project_role_permission_bundle_scope_mismatch"}
	}

	workspaceID := strings.TrimSpace(string(request.Application.WorkspaceID))
	ctx = requestcontext.WithWorkspaceID(ctx, workspaceID)
	principal := identitymodel.Principal{
		Known: true, WorkspaceID: workspaceID, UserID: strings.TrimSpace(string(request.ActorID)),
		Role: identitymodel.RoleSchema{Key: "project_permission_bundle_publisher", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, identitycontract.IdentityActionRolePermissionsPublish)},
	}
	roleKey := strings.TrimSpace(request.RoleKey)
	current, revision, found, err := binding.runtime.Metadata.IdentityRolePermissionDefinitionForPublication(ctx, roleKey, principal)
	if err != nil {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, err
	}
	if !found {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassNotFound, Code: "identity.project_role_permission_bundle_role_not_found", Params: map[string]string{"role_key": roleKey}}
	}

	permissionKeys := make([]string, 0, len(request.Permissions))
	for _, permission := range request.Permissions {
		permissionKeys = append(permissionKeys, strings.TrimSpace(permission.PermissionKey))
	}
	if err := binding.runtime.PermissionCatalog.ValidatePermissionSelections(permissionKeys); err != nil {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, err
	}

	permissions := append([]identitymodel.RolePermission(nil), current.Permissions...)
	existing := make(map[string]int, len(permissions))
	for index, permission := range permissions {
		existing[strings.TrimSpace(permission.PermissionKey)] = index
	}
	added, updatedCount := 0, 0
	for _, permission := range request.Permissions {
		key := strings.TrimSpace(permission.PermissionKey)
		next := identitymodel.RolePermission{
			PermissionKey: key,
			DataScope:     identitymodel.IdentityDataScope(permission.DataScope),
			DataPolicy:    permission.DataPolicy,
			AuditDenial:   permission.AuditDenial,
		}
		if index, found := existing[key]; found {
			if !reflect.DeepEqual(permissions[index], next) {
				permissions[index] = next
				updatedCount++
			}
			continue
		}
		existing[key] = len(permissions)
		added++
		permissions = append(permissions, next)
	}
	permissions, valid := identitymodel.NormalizeRolePermissions(permissions)
	if !valid {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.project_role_permission_bundle_invalid"}
	}
	if added == 0 && updatedCount == 0 {
		return identitysdk.ProjectRolePermissionBundleReceipt{RoleKey: roleKey, PermissionCount: len(permissions), SchemaVersion: revision.SchemaVersion, SchemaHash: revision.SchemaHash}, nil
	}

	updatedRevision, err := binding.runtime.Metadata.PublishIdentityRolePermissions(ctx, roleKey, permissions, revision.SchemaHash, strings.TrimSpace(request.BusinessReason), strings.TrimSpace(request.OperationID), principal)
	if err != nil {
		return identitysdk.ProjectRolePermissionBundleReceipt{}, err
	}
	return identitysdk.ProjectRolePermissionBundleReceipt{RoleKey: roleKey, Added: added, Updated: updatedCount, PermissionCount: len(permissions), SchemaVersion: updatedRevision.SchemaVersion, SchemaHash: updatedRevision.SchemaHash}, nil
}
