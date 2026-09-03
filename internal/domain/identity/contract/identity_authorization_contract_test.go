package contract

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityDataScopeBelongsToExactFunctionalAction(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOrg, "invoice.read")}
	if scopes := IdentityDataScopesForAction(role, "invoice", "read"); len(scopes) != 1 || scopes[0] != identitymodel.IdentityDataScopeOrg {
		t.Fatalf("scopes=%q", scopes)
	}
	if scopes := IdentityDataScopesForAction(role, "invoice", "update"); len(scopes) != 0 {
		t.Fatalf("read scope leaked to update: %q", scopes)
	}
}

func TestExactPermissionDoesNotExpandToAnotherAction(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list", "identity.users.list")}
	if IdentityRoleHasPermissionKey(role, "runtime.worker.control") {
		t.Fatal("unrelated Permission expanded into a Runtime Ops capability")
	}
	role.Permissions = append(role.Permissions, identitymodel.RolePermission{PermissionKey: "runtime.worker.*", DataScope: identitymodel.IdentityDataScopeAll})
	if IdentityRoleHasPermissionKey(role, "runtime.worker.control") {
		t.Fatal("resource wildcard expanded into a different Action permission")
	}
}

func TestGuardrailDenyOverridesPositiveGrant(t *testing.T) {
	role := identitymodel.RoleSchema{
		Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list", "payment.read", "payment.update", "payment.approve"),
		Guardrails: []identitymodel.IdentityGuardrailPolicy{{
			Key:                  "separation_of_duties",
			DeniedPermissionKeys: []string{"payment.approve"},
			DataRestrictions:     []identitymodel.IdentityDataRestriction{{ObjectKey: "payment", Actions: []string{"update"}}},
			FieldRestrictions:    []identitymodel.IdentityFieldRestriction{{ObjectKey: "payment", FieldKey: "bank_account", Actions: []string{"read", "export"}}},
		}},
	}
	if IdentityRoleHasPermissionKey(role, "payment.approve") || IdentityRoleAllows(role, "payment", "approve") {
		t.Fatal("guardrail did not override positive function grant")
	}
	if !IdentityRoleHasPermissionKey(role, "identity.roles.list") || !IdentityRoleAllowsData(role, "payment", "read") || IdentityRoleAllowsData(role, "payment", "update") {
		t.Fatal("guardrail data action decision mismatch")
	}
	if !IdentityRoleGuardrailDeniesField(role, "payment", "bank_account", "read") ||
		!IdentityRoleGuardrailDeniesField(role, "payment", "bank_account", "export") ||
		IdentityRoleGuardrailDeniesField(role, "payment", "bank_account", "view") ||
		IdentityRoleGuardrailDeniesField(role, "payment", "amount", "read") {
		t.Fatal("guardrail field decision mismatch")
	}
}

func TestIdentityAuthorizationContractRemainingShortCircuitOutcomes(t *testing.T) {
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{}, " ") {
		t.Fatal("blank exact permission accepted")
	}
	denied := identitymodel.RoleSchema{
		Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "payment.approve"),
		Guardrails: []identitymodel.IdentityGuardrailPolicy{{
			DeniedPermissionKeys: []string{"payment.approve"},
		}},
	}
	if IdentityRoleHasPermissionKey(denied, "payment.approve") {
		t.Fatal("guardrail did not deny exact permission")
	}
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "*")}, "runtime.worker.control") {
		t.Fatal("global wildcard expanded into an exact Action permission")
	}
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "runtime.worker.*")}, "runtime.scheduler.control") {
		t.Fatal("unrelated exact wildcard was honored")
	}

	if !IdentityRoleGuardrailDeniesPermission(identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{
		DeniedPermissionKeys: []string{"*"},
	}}}, "anything.read") {
		t.Fatal("global guardrail wildcard was not honored")
	}
	wildcardGuardrail := identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{
		DeniedPermissionKeys: []string{"payment.*"},
	}}}
	if !IdentityRoleGuardrailDeniesPermission(wildcardGuardrail, "payment.read") {
		t.Fatal("matching guardrail wildcard was not honored")
	}
	if IdentityRoleGuardrailDeniesPermission(wildcardGuardrail, "invoice.read") {
		t.Fatal("unrelated guardrail wildcard was honored")
	}

	restrictions := identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{
		DataRestrictions: []identitymodel.IdentityDataRestriction{
			{ObjectKey: "invoice", Actions: []string{"*"}},
			{ObjectKey: "payment", Actions: []string{"*"}},
		},
		FieldRestrictions: []identitymodel.IdentityFieldRestriction{
			{ObjectKey: "invoice", FieldKey: "secret", Actions: []string{"read"}},
			{ObjectKey: "payment", FieldKey: "secret", Actions: []string{"*"}},
		},
	}}}
	if !IdentityRoleGuardrailDeniesData(restrictions, "payment", "update") {
		t.Fatal("data wildcard action was not honored")
	}
	if IdentityRoleGuardrailDeniesData(restrictions, "customer", "read") {
		t.Fatal("unrelated data restriction was honored")
	}
	if !IdentityRoleGuardrailDeniesField(restrictions, "payment", "secret", "update") {
		t.Fatal("field wildcard action was not honored")
	}
	if IdentityRoleGuardrailDeniesField(restrictions, "customer", "secret", "read") {
		t.Fatal("unrelated field restriction was honored")
	}
}

func TestIdentityAuthorizationContractLocalDecisionMatrix(t *testing.T) {
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{}, "") {
		t.Fatal("blank permission accepted")
	}
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "*")}, "invoice.read") {
		t.Fatal("global wildcard expanded into an Action permission")
	}
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "invoice.*")}, "invoice.read") {
		t.Fatal("resource wildcard expanded into an Action permission")
	}
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "invoice.*")}, "payment.read") {
		t.Fatal("unrelated permission wildcard was honored")
	}
	if !IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "runtime.worker.control")}, "runtime.worker.control") {
		t.Fatal("positive exact permission was not honored")
	}

	if !IdentityRoleAllows(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "invoice.read")}, "invoice", "read") {
		t.Fatal("direct object action was not honored")
	}
	if IdentityRoleAllows(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "action.invoice.view")}, "invoice", "read") {
		t.Fatal("legacy qualified permission was treated as invoice.read")
	}
	if IdentityRoleAllows(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "invoice.update")}, "invoice", "edit") {
		t.Fatal("legacy edit alias was treated as invoice.update")
	}
	if IdentityRoleAllows(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "action.payment.view")}, "invoice", "read") {
		t.Fatal("qualified permission for another object was honored")
	}
	if IdentityRoleAllows(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "unrelated", "action.invoice.delete")}, "invoice", "read") {
		t.Fatal("unrelated permission shape or action was honored")
	}

	dataRole := identitymodel.RoleSchema{Permissions: []identitymodel.RolePermission{
		{PermissionKey: "other.read", DataScope: identitymodel.IdentityDataScopeAll},
		{PermissionKey: "invoice.read", DataScope: identitymodel.IdentityDataScopeOrg},
		{PermissionKey: "invoice.update", DataScope: identitymodel.IdentityDataScopeOwner},
	}}
	if !IdentityRoleAllowsData(dataRole, "invoice", "read") {
		t.Fatal("object data policy was not honored for read")
	}
	if !IdentityRoleAllowsData(dataRole, "invoice", "update") {
		t.Fatal("object data policy was not honored for update")
	}
	if IdentityRoleAllowsData(dataRole, "customer", "read") {
		t.Fatal("data permission for another object was honored")
	}
	if IdentityRoleAllowsData(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "other.read")}, "invoice", "read") {
		t.Fatal("data policy for another object was honored")
	}

	fieldMismatchAction := identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{
		FieldRestrictions: []identitymodel.IdentityFieldRestriction{{
			ObjectKey: "invoice", FieldKey: "secret", Actions: []string{"update"},
		}},
	}}}
	if IdentityRoleGuardrailDeniesField(fieldMismatchAction, "invoice", "secret", "read") {
		t.Fatal("field restriction for another action was honored")
	}

	if scopes := IdentityDataScopesForAction(identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")}, "invoice", "read"); len(scopes) != 0 {
		t.Fatalf("functional Permission expanded into data scopes=%q", scopes)
	}
	scopeRole := identitymodel.RoleSchema{Permissions: []identitymodel.RolePermission{
		{PermissionKey: "invoice.export", DataScope: identitymodel.IdentityDataScopeOrg},
		{PermissionKey: "invoice.export", DataScope: identitymodel.IdentityDataScopeOwner},
	}}
	if scopes := IdentityDataScopesForAction(scopeRole, "invoice", "export"); len(scopes) != 2 {
		t.Fatalf("combined scopes=%q", scopes)
	}
}

func TestIdentityPermissionDataScopeAllowsUsesTheFiveCanonicalScopes(t *testing.T) {
	facts := IdentityResourceFacts{RecordID: "assignment-1", OwnerUserID: "user", OwnerOrgID: "sales-east"}
	tests := []struct {
		scope     identitymodel.IdentityDataScope
		principal identitymodel.Principal
	}{
		{identitymodel.IdentityDataScopeAll, identitymodel.Principal{Known: true, UserID: "actor"}},
		{identitymodel.IdentityDataScopeOwner, identitymodel.Principal{Known: true, UserID: "user"}},
		{identitymodel.IdentityDataScopeOrg, identitymodel.Principal{Known: true, UserID: "actor", OrgID: "sales-east"}},
		{identitymodel.IdentityDataScopeOrgChild, identitymodel.Principal{Known: true, UserID: "actor", OrgScopeIDs: []string{"sales", "sales-east"}}},
		{identitymodel.IdentityDataScopeTargetOrg, identitymodel.Principal{Known: true, UserID: "actor", SupportOrgScopeIDs: []string{"sales", "sales-east"}}},
	}
	for _, test := range tests {
		test.principal.Role.Permissions = identitymodel.RolePermissionsWithScope(test.scope, IdentityUserRoleAssignmentsAssignPermission)
		if !IdentityPermissionDataScopeAllows(test.principal, IdentityUserRoleAssignmentsAssignPermission, facts) {
			t.Errorf("scope %q denied matching facts", test.scope)
		}
	}
	denied := tests[4].principal
	denied.SupportOrgScopeIDs = []string{"other"}
	if IdentityPermissionDataScopeAllows(denied, IdentityUserRoleAssignmentsAssignPermission, facts) {
		t.Fatal("target_org expanded beyond support organization scope")
	}
}
