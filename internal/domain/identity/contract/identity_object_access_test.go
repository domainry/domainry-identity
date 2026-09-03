package contract

import (
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestWorkspaceAdminShapedPermissionDoesNotGrantFieldAuthority(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "workspace.admin")}
	object := definitionmodel.ObjectSchema{
		Key:    "payment",
		Config: map[string]any{"field_access_mode": "default_deny"},
	}
	field := definitionmodel.FieldSchema{Key: "bank_account", Type: "string", Config: map[string]any{"sensitive": true}}

	if IdentityCanReadObjectField(role, object, field) ||
		IdentityCanWriteObjectField(role, object, field) ||
		IdentityCanExportObjectField(role, object, field) {
		t.Fatal("workspace.admin must not bypass explicit field authorization")
	}

	role.FieldPermissions = []identitymodel.FieldPermission{{
		ObjectKey: "payment", FieldKey: "bank_account", Read: true, Masked: true,
	}}
	if !IdentityCanReadObjectField(role, object, field) || IdentityCanWriteObjectField(role, object, field) || IdentityCanExportObjectField(role, object, field) {
		t.Fatal("field authority must come only from the explicit field policy")
	}
	if !IdentityFieldReadMasked(role, object.Key, field.Key) {
		t.Fatal("workspace.admin must not bypass the explicit field mask")
	}
}
