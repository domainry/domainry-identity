package identity

import (
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestStandaloneAuthorizationSliceRegistryOwnsCompleteRouteAndPermissionMatrix(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	definitions := registry.Definitions()
	if len(definitions) != 126 {
		t.Fatalf("Identity Action count=%d want=126", len(definitions))
	}
	seenHTTP := map[string]string{}
	pageBindings := 0
	nonHTTPBindings := 0
	for _, definition := range definitions {
		if len(definition.Pages) != 0 {
			pageBindings++
		}
		if definition.HTTP == nil {
			if len(definition.NonHTTP) != 1 {
				t.Fatalf("non-HTTP action %q binding=%v permission=%v", definition.Key, definition.NonHTTP, definition.Permission)
			}
			if definition.Key == "identity.workspace_identity_usage.aggregate" {
				if definition.Permission != nil || definition.Authorization.Strategy != actioncontract.AuthorizationSigned || definition.Authorization.PolicyKey != definition.Key {
					t.Fatalf("installation usage action %q must use only its signed policy key: %+v", definition.Key, definition)
				}
			} else if definition.Permission == nil || definition.Permission.Key != definition.Key {
				t.Fatalf("non-HTTP action %q permission=%v", definition.Key, definition.Permission)
			}
			nonHTTPBindings++
			continue
		}
		binding := definition.HTTP.Method + " " + definition.HTTP.RouteTemplate
		if previous := seenHTTP[binding]; previous != "" {
			t.Fatalf("HTTP binding %q is shared by %q and %q", binding, previous, definition.Key)
		}
		seenHTTP[binding] = definition.Key
		switch definition.Authorization.Strategy {
		case actioncontract.AuthorizationAnonymous:
			if definition.Permission != nil {
				t.Fatalf("anonymous action %q owns permission", definition.Key)
			}
		case actioncontract.AuthorizationAuthenticated:
			if definition.Permission != nil && definition.Permission.Key != definition.Key {
				t.Fatalf("action %q permission=%v", definition.Key, definition.Permission)
			}
		default:
			t.Fatalf("Identity action %q strategy=%q", definition.Key, definition.Authorization.Strategy)
		}
	}
	if pageBindings != 7 {
		t.Fatalf("page-bound Identity Actions=%d want=7", pageBindings)
	}
	if nonHTTPBindings != 20 {
		t.Fatalf("non-HTTP Identity Actions=%d want=20", nonHTTPBindings)
	}
	for key, binding := range map[string]string{
		"auth.session.get":                        "GET /auth/session",
		"auth.code.exchange":                      "POST /auth/code/exchange",
		"identity.users.create":                   "POST /identity/users",
		"identity.users.force_logout":             "POST /identity/users/{userID}/force-logout",
		"identity.organization_units.update":      "PATCH /identity/organization-units/{organizationUnitID}",
		"identity.role_permissions.publish":       "PUT /identity/roles/{roleID}/permissions",
		"identity.roles.create":                   "POST /identity/roles",
		"identity.roles.update":                   "PATCH /identity/roles/{roleID}",
		"identity.roles.delete":                   "DELETE /identity/roles/{roleID}",
		"identity.role_field_permissions.publish": "PUT /identity/roles/{roleID}/field-permissions",
		"identity.access_review_items.decide":     "POST /identity/access-review-items/{itemID}/decision",
		"identity.profile_bindings.command":       "POST /identity/profile-bindings/{objectKey}/{profileID}/commands",
		"identity.user_role_assignments.revoke":   "DELETE /identity/users/{userID}/role-assignments/{roleID}",
	} {
		definition, found := registry.Definition(key)
		if !found || definition.HTTP.Method+" "+definition.HTTP.RouteTemplate != binding {
			t.Fatalf("Action %q binding=%v found=%v want=%q", key, definition.HTTP, found, binding)
		}
	}
	permissions := registry.OwnedPermissionDefinitions(IdentityBuiltinAuthorizationOwner)
	if len(permissions) != 95 {
		t.Fatalf("owned permission count=%d want=95", len(permissions))
	}
	for _, key := range []string{
		"identity.handler_delivery.create", "identity.handler_delivery.update",
		"identity.handler_delivery.disable", "identity.handler_delivery.resolve",
	} {
		definition, found := registry.Definition(key)
		if !found || definition.HTTP != nil || len(definition.NonHTTP) != 1 || definition.NonHTTP[0].InvocationKey != key {
			t.Fatalf("HandlerDelivery Action %q must be non-HTTP and purpose-specific: found=%v definition=%+v", key, found, definition)
		}
	}
	usage, found := registry.Definition("identity.workspace_identity_usage.aggregate")
	if !found || usage.HTTP != nil || len(usage.NonHTTP) != 1 || usage.Authorization.Strategy != actioncontract.AuthorizationSigned || usage.Authorization.PolicyKey != usage.Key || usage.Permission != nil {
		t.Fatalf("Workspace usage Action is not an exact purpose-specific non-HTTP permission: found=%v definition=%+v", found, usage)
	}
	for _, key := range []string{
		"identity.store_organization_delivery.create", "identity.store_organization_delivery.rename",
		"identity.store_organization_delivery.disable", "identity.store_organization_delivery.resolve",
		"identity.store_organization_delivery.list",
	} {
		definition, found := registry.Definition(key)
		if !found || definition.HTTP != nil || len(definition.NonHTTP) != 1 || definition.NonHTTP[0].InvocationKey != key {
			t.Fatalf("StoreOrganization Action %q must be non-HTTP and purpose-specific: found=%v definition=%+v", key, found, definition)
		}
	}
	for _, permission := range permissions {
		if len(registry.PermissionUsages(permission.PermissionKey)) == 0 {
			t.Fatalf("permission %q has no live action usage", permission.PermissionKey)
		}
	}
	for route, permission := range map[string]string{
		"/admin/security/accounts":         "identity.users.list",
		"/admin/security/accounts/$userId": "identity.users.get",
		"/admin/org/organization-units":    "identity.organization_units.list",
		"/admin/org/roles":                 "identity.roles.list",
		"/admin/org/menus":                 "identity.menus.list",
		"/admin/org/field-permissions":     "identity.role_field_permissions.list",
		"/admin/system/metadata":           "identity.metadata.migration_plan.get",
	} {
		required, found := registry.RequiredPermissionsForPage(route)
		if !found || len(required) != 1 || required[0] != permission {
			t.Fatalf("page %q required=%v found=%v want=%q", route, required, found, permission)
		}
	}
	accessGovernance, found := registry.RequiredPermissionsForPage("/admin/security/access-governance")
	if !found || len(accessGovernance) != 4 {
		t.Fatalf("access governance page required=%v found=%v", accessGovernance, found)
	}
}

func TestIdentityActionRegistryRejectsDuplicateActionsAndMismatchedPermission(t *testing.T) {
	var action identitymodel.IdentityActionDefinition
	for _, candidate := range StandaloneIdentityAuthorizationSliceActions() {
		if candidate.Key == "identity.organization_units.list" {
			action = candidate
			break
		}
	}
	if action.Key == "" {
		t.Fatal("test Action is missing")
	}
	duplicate := actioncontract.CloneDefinition(action)
	duplicate.Key = action.Key
	duplicate.HTTP.RouteTemplate = "/identity/roles-duplicate"
	if _, err := NewIdentityActionRegistry([]identitymodel.IdentityActionDefinition{action, duplicate}); err == nil {
		t.Fatal("duplicate permission ownership accepted")
	}
	mismatched := actioncontract.CloneDefinition(action)
	mismatched.Permission.Key = "identity.unknown"
	if _, err := NewIdentityActionRegistry([]identitymodel.IdentityActionDefinition{mismatched}); err == nil {
		t.Fatal("mismatched action permission accepted")
	}
	pageCollision := actioncontract.CloneDefinition(action)
	pageCollision.Key = "identity.organization_units.other_list"
	pageCollision.OperationKey = "other_list"
	pageCollision.HTTP.RouteTemplate = "/identity/organization-units-other"
	pageCollision.Permission.Key = pageCollision.Key
	pageCollision.Permission.OperationKey = pageCollision.OperationKey
	if _, err := NewIdentityActionRegistry([]identitymodel.IdentityActionDefinition{action, pageCollision}); err == nil {
		t.Fatal("duplicate page entry Action accepted")
	}
}

func TestIdentityActionAuthorizationUsesOnlySameKeyDatabaseBackedGrant(t *testing.T) {
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	repository := &permissionCatalogRepositoryStub{}
	catalog, err := NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.ReconcileOwner(t.Context(), IdentityBuiltinAuthorizationOwner); err != nil {
		t.Fatal(err)
	}
	authorizer := NewIdentityActionAuthorizationService(registry, catalog)
	definition := func(key string) identitymodel.IdentityActionDefinition {
		t.Helper()
		action, found := registry.Definition(key)
		if !found {
			t.Fatalf("Action %q is not registered", key)
		}
		return action
	}

	exact := definition("identity.permissions.list")
	if authorizer.Allows(exact, identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions("identity.roles.list")}}, IdentityActionAuthorizationContext{}) {
		t.Fatal("another exact Permission expanded into the requested Action")
	}
	if !authorizer.Allows(exact, identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(exact.Key)}}, IdentityActionAuthorizationContext{}) {
		t.Fatal("same-key active database Permission was denied")
	}
	for index := range repository.records {
		if repository.records[index].PermissionKey == exact.Key {
			repository.records[index].Enabled = false
		}
	}
	if err := catalog.ReloadCurrentSnapshot(t.Context()); err != nil {
		t.Fatal(err)
	}
	if authorizer.Allows(exact, identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(exact.Key)}}, IdentityActionAuthorizationContext{}) {
		t.Fatal("disabled database Permission remained executable")
	}

	if !authorizer.Allows(definition("auth.login"), identitymodel.Principal{}, IdentityActionAuthorizationContext{}) {
		t.Fatal("registered anonymous protocol Action was denied")
	}
	if authorizer.Allows(definition("auth.me.get"), identitymodel.Principal{}, IdentityActionAuthorizationContext{}) ||
		!authorizer.Allows(definition("auth.me.get"), identitymodel.Principal{Known: true}, IdentityActionAuthorizationContext{}) {
		t.Fatal("authenticated-principal Action did not follow principal identity")
	}
	self := definition("identity.users.get")
	if authorizer.Allows(self, identitymodel.Principal{Known: true}, IdentityActionAuthorizationContext{}) {
		t.Fatal("registered self policy bypassed the exact Permission grant")
	}
	if !authorizer.Allows(self, identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(self.Key)}}, IdentityActionAuthorizationContext{}) {
		t.Fatal("self Action with an exact scoped Permission was denied at the function gate")
	}
}
