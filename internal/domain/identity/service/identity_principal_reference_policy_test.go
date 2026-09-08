package service

import (
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestBuildPrincipalDeduplicatesIdenticalReferencesAcrossRoles(t *testing.T) {
	repository, service := identityRolesFixture()
	reference := identitymodel.ReferencePermission{
		SourceObjectKey: "member", RelationFieldKey: "store_id", TargetObjectKey: "store",
		Mode: "selected_fields", DisplayFields: []string{"name"},
	}
	definitions := []identitymodel.RoleSchema{
		{Key: "member", ReferencePermissions: []identitymodel.ReferencePermission{reference}},
		{Key: "viewer", ReferencePermissions: []identitymodel.ReferencePermission{reference}},
	}
	service.ReplaceRoleDefinitions(definitions)
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "member-id"},
		{UserID: "user-1", RoleID: "viewer-id"},
	}
	principal, err := service.BuildPrincipal(t.Context(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || principal.Role.Key != "identity_effective" {
		t.Fatalf("combined principal=%+v", principal)
	}
	if want := []identitymodel.ReferencePermission{reference}; !reflect.DeepEqual(principal.Role.ReferencePermissions, want) {
		t.Fatalf("combined references=%+v want=%+v", principal.Role.ReferencePermissions, want)
	}
	if len(definitions[0].ReferencePermissions) != 1 || len(definitions[1].ReferencePermissions) != 1 {
		t.Fatal("published role definitions were changed")
	}
}

func TestEffectiveRoleReferenceDeduplicationPreservesConflicts(t *testing.T) {
	allow := identitymodel.ReferencePermission{SourceObjectKey: "member", RelationFieldKey: "store_id", TargetObjectKey: "store", Mode: "selected_fields", DisplayFields: []string{"name"}}
	deny := allow
	deny.Mode, deny.Reason = "deny", "restricted"
	role := identitymodel.RoleSchema{ReferencePermissions: []identitymodel.ReferencePermission{allow, deny, allow, deny}}
	identityCanonicalizeEffectiveRole(&role)
	if len(role.ReferencePermissions) != 2 {
		t.Fatalf("exact duplicates should collapse while conflicting policies remain: %+v", role.ReferencePermissions)
	}
	seen := map[string]bool{}
	for _, reference := range role.ReferencePermissions {
		seen[reference.Mode] = true
	}
	if !seen["deny"] || !seen["selected_fields"] {
		t.Fatalf("a conflicting policy was discarded: %+v", role.ReferencePermissions)
	}
}
