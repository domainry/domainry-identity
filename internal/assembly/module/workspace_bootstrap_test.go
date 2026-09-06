package moduleassembly

import (
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func TestWorkspaceBootstrapVolatileCredentialReplacementAndDiscardDoNotAccumulate(t *testing.T) {
	binding := &moduleBinding{}
	binding.storeWorkspaceBootstrapCredential("receipt", "workspace", "first@example.test", []byte("FirstPassword1!"))
	first := binding.bootstrapCredentials["receipt"]
	binding.storeWorkspaceBootstrapCredential("receipt", "workspace", "second@example.test", []byte("SecondPassword1!"))
	if len(binding.bootstrapCredentials) != 1 {
		t.Fatalf("pending credentials=%d", len(binding.bootstrapCredentials))
	}
	binding.expireWorkspaceBootstrapCredential("receipt", first)
	if binding.bootstrapCredentials["receipt"] == nil {
		t.Fatal("stale expiry removed the replacement credential")
	}
	for _, value := range first.password {
		if value != 0 {
			t.Fatal("replaced volatile credential was not zeroed")
		}
	}
	current := binding.bootstrapCredentials["receipt"]
	binding.discardWorkspaceBootstrapCredential("receipt")
	if len(binding.bootstrapCredentials) != 0 {
		t.Fatalf("pending credentials after discard=%d", len(binding.bootstrapCredentials))
	}
	for _, value := range current.password {
		if value != 0 {
			t.Fatal("discarded volatile credential was not zeroed")
		}
	}
}

func TestWorkspaceBootstrapRoleCatalogDigestIsCanonicalAndAuthorizationComplete(t *testing.T) {
	roles := []identitysdk.ProjectRoleDefinition{
		{
			Key: "admin", Name: "Administrator", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true, SchemaHash: "schema-admin",
			Permissions: []identitysdk.ProjectRolePermission{
				{PermissionKey: "customer.write", DataScope: identitysdk.DataScopeOrg},
				{PermissionKey: "customer.read", DataScope: identitysdk.DataScopeAll},
			},
			PermissionSetKeys: []string{"write", "read"},
		},
		{Key: "member", Name: "Member", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true, SchemaHash: "schema-member"},
	}
	digest := func(inputs []identitysdk.ProjectRoleDefinition, administrator string) string {
		t.Helper()
		definitions, err := projectRoleDefinitions(inputs)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := newWorkspaceBootstrapRoleCatalog(inputs, definitions, administrator)
		if err != nil {
			t.Fatal(err)
		}
		return catalog.sha256
	}
	want := digest(roles, "admin")
	reordered := []identitysdk.ProjectRoleDefinition{roles[1], roles[0]}
	reordered[1].Permissions = []identitysdk.ProjectRolePermission{roles[0].Permissions[1], roles[0].Permissions[0]}
	reordered[1].PermissionSetKeys = []string{"read", "write"}
	if got := digest(reordered, "admin"); got != want {
		t.Fatalf("semantic reordering changed role catalog digest: got=%s want=%s", got, want)
	}
	changedSchema := append([]identitysdk.ProjectRoleDefinition(nil), roles...)
	changedSchema[0].SchemaHash = "schema-admin-changed"
	if got := digest(changedSchema, "admin"); got == want {
		t.Fatal("schema hash drift was absent from role catalog digest")
	}
	changedPermission := append([]identitysdk.ProjectRoleDefinition(nil), roles...)
	changedPermission[0].Permissions = append([]identitysdk.ProjectRolePermission(nil), roles[0].Permissions...)
	changedPermission[0].Permissions[0].DataScope = identitysdk.DataScopeAll
	if got := digest(changedPermission, "admin"); got == want {
		t.Fatal("permission drift was absent from role catalog digest")
	}
	if got := digest(roles, "member"); got == want {
		t.Fatal("administrator role drift was absent from role catalog digest")
	}
}
