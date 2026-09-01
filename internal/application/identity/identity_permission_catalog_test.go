package identity

import (
	"slices"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestPermissionDefinitionAndSnapshotHashesAreCanonical(t *testing.T) {
	definition := identitymodel.IdentityPermissionDefinitionRecord{
		PermissionKey: "identity.roles.read", ResourceKey: "roles", ActionKey: "read", Label: "Role read",
		Description: "Read roles", Category: "Identity", SourceKind: "builtin_surface", SourceOwner: "identity:builtin",
	}
	first, err := IdentityPermissionDefinitionHash(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Enabled = false
	definition.ID = "database-row"
	definition.UpdatedAt = "later"
	second, err := IdentityPermissionDefinitionHash(definition)
	if err != nil || first != second {
		t.Fatalf("source hash changed with administrator/database fields: %q %q err=%v", first, second, err)
	}
	left := []identitymodel.IdentityPermissionDefinitionRecord{{PermissionKey: "b", DefinitionHash: "2"}, {PermissionKey: "a", DefinitionHash: "1"}}
	right := slices.Clone(left)
	slices.Reverse(right)
	leftHash, err := IdentityPermissionSourceSnapshotHash(left)
	if err != nil {
		t.Fatal(err)
	}
	rightHash, err := IdentityPermissionSourceSnapshotHash(right)
	if err != nil || leftHash != rightHash {
		t.Fatalf("snapshot hash is order dependent: %q %q err=%v", leftHash, rightHash, err)
	}
}

func TestNewRolePermissionSelectionsRequireCurrentSelectableDefinitions(t *testing.T) {
	service := &IdentityPermissionCatalogApplicationService{}
	service.snapshot.Store(&identityPermissionRuntimeSnapshot{byKey: map[string]identityPermissionRuntimeState{
		"active":   {active: true, enabled: true},
		"disabled": {active: true, enabled: false},
		"retired":  {active: false, enabled: true},
	}})
	if err := service.ValidateNewPermissionSelections([]string{"legacy", "disabled", "retired"}, []string{"legacy", "disabled", "retired", "active"}); err != nil {
		t.Fatalf("retained legacy state or new active permission rejected: %v", err)
	}
	for _, test := range []struct {
		key  string
		code string
	}{
		{key: "missing", code: "backend.identity.permission_not_found"},
		{key: "disabled", code: "backend.identity.permission_disabled"},
		{key: "retired", code: "backend.identity.permission_retired"},
	} {
		if err := service.ValidateNewPermissionSelections(nil, []string{test.key}); apperror.CodeOf(err) != test.code {
			t.Fatalf("selection %q error=%v code=%q", test.key, err, apperror.CodeOf(err))
		}
	}
}
