package contract

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityDataScopeRejectsUnreadableDataPermission(t *testing.T) {
	role := identitymodel.RoleSchema{DataPermissions: []identitymodel.DataPermission{{ObjectKey: "invoice", Scope: "department"}}}
	if scope := IdentityDataScope(role, "invoice", false); scope != "none" {
		t.Fatalf("read scope=%q", scope)
	}
}

func TestExactPermissionDoesNotExpandWorkspaceAdministrator(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: []string{"workspace.admin", "identity.users.read"}}
	if IdentityRoleHasExactPermissionKey(role, "runtime.worker.control") {
		t.Fatal("workspace.admin expanded into a Runtime Ops capability")
	}
	role.Permissions = append(role.Permissions, "runtime.worker.*")
	if !IdentityRoleHasExactPermissionKey(role, "runtime.worker.control") {
		t.Fatal("explicit Runtime Ops wildcard was not honored")
	}
}

func TestGuardrailDenyOverridesPositiveGrantAndWorkspaceAdministrator(t *testing.T) {
	role := identitymodel.RoleSchema{
		Permissions:     []string{"workspace.admin", "payment.approve"},
		DataPermissions: []identitymodel.DataPermission{{ObjectKey: "payment", Scope: "all_records", Read: true, Write: true}},
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
	if !IdentityRoleHasPermissionKey(role, "workspace.admin") || !IdentityRoleAllowsData(role, "payment", "read") || IdentityRoleAllowsData(role, "payment", "update") {
		t.Fatal("guardrail data action decision mismatch")
	}
	if !IdentityRoleGuardrailDeniesField(role, "payment", "bank_account", "view") ||
		!IdentityRoleGuardrailDeniesField(role, "payment", "bank_account", "export") ||
		IdentityRoleGuardrailDeniesField(role, "payment", "amount", "read") {
		t.Fatal("guardrail field decision mismatch")
	}
}

func TestIdentityAuthorizationContractRemainingShortCircuitOutcomes(t *testing.T) {
	if IdentityRoleHasExactPermissionKey(identitymodel.RoleSchema{}, " ") {
		t.Fatal("blank exact permission accepted")
	}
	denied := identitymodel.RoleSchema{
		Permissions: []string{"payment.approve"},
		Guardrails: []identitymodel.IdentityGuardrailPolicy{{
			DeniedPermissionKeys: []string{"payment.approve"},
		}},
	}
	if IdentityRoleHasExactPermissionKey(denied, "payment.approve") {
		t.Fatal("guardrail did not deny exact permission")
	}
	if !IdentityRoleHasExactPermissionKey(identitymodel.RoleSchema{Permissions: []string{"*"}}, "runtime.worker.control") {
		t.Fatal("global exact wildcard was not honored")
	}
	if IdentityRoleHasExactPermissionKey(identitymodel.RoleSchema{Permissions: []string{"runtime.worker.*"}}, "runtime.scheduler.control") {
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
	if !IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: []string{"*"}}, "invoice.read") {
		t.Fatal("global permission wildcard was not honored")
	}
	if !IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: []string{"invoice.*"}}, "invoice.read") {
		t.Fatal("matching permission wildcard was not honored")
	}
	if IdentityRoleHasPermissionKey(identitymodel.RoleSchema{Permissions: []string{"invoice.*"}}, "payment.read") {
		t.Fatal("unrelated permission wildcard was honored")
	}
	if !IdentityRoleHasExactPermissionKey(identitymodel.RoleSchema{Permissions: []string{"runtime.worker.control"}}, "runtime.worker.control") {
		t.Fatal("positive exact permission was not honored")
	}

	if !IdentityRoleAllows(identitymodel.RoleSchema{Permissions: []string{"invoice.read"}}, "invoice", "read") {
		t.Fatal("direct object action was not honored")
	}
	if !IdentityRoleAllows(identitymodel.RoleSchema{Permissions: []string{"action.invoice.view"}}, "invoice", "read") {
		t.Fatal("qualified legacy view action was not normalized")
	}
	if !IdentityRoleAllows(identitymodel.RoleSchema{Permissions: []string{"invoice.update"}}, "invoice", "edit") {
		t.Fatal("legacy edit action was not normalized")
	}
	if IdentityRoleAllows(identitymodel.RoleSchema{Permissions: []string{"action.payment.view"}}, "invoice", "read") {
		t.Fatal("qualified permission for another object was honored")
	}
	if IdentityRoleAllows(identitymodel.RoleSchema{Permissions: []string{"unrelated", "action.invoice.delete"}}, "invoice", "read") {
		t.Fatal("unrelated permission shape or action was honored")
	}

	dataRole := identitymodel.RoleSchema{DataPermissions: []identitymodel.DataPermission{
		{ObjectKey: "other", Read: true, Write: true},
		{ObjectKey: "invoice", Read: true},
		{ObjectKey: "invoice", Write: true},
	}}
	if !IdentityRoleAllowsData(dataRole, "invoice", "read") {
		t.Fatal("read data permission was not honored")
	}
	if !IdentityRoleAllowsData(dataRole, "invoice", "update") {
		t.Fatal("write data permission was not honored")
	}
	if IdentityRoleAllowsData(dataRole, "customer", "read") {
		t.Fatal("data permission for another object was honored")
	}
	if IdentityRoleAllowsData(identitymodel.RoleSchema{DataPermissions: []identitymodel.DataPermission{{
		ObjectKey: "invoice", Read: false,
	}}}, "invoice", "read") {
		t.Fatal("disabled read data permission was honored")
	}

	fieldMismatchAction := identitymodel.RoleSchema{Guardrails: []identitymodel.IdentityGuardrailPolicy{{
		FieldRestrictions: []identitymodel.IdentityFieldRestriction{{
			ObjectKey: "invoice", FieldKey: "secret", Actions: []string{"update"},
		}},
	}}}
	if IdentityRoleGuardrailDeniesField(fieldMismatchAction, "invoice", "secret", "read") {
		t.Fatal("field restriction for another action was honored")
	}

	if scope := IdentityDataScope(identitymodel.RoleSchema{Permissions: []string{"workspace.admin"}}, "invoice", false); scope != "all_records" {
		t.Fatalf("administrator scope=%q", scope)
	}
	scopeRole := identitymodel.RoleSchema{DataPermissions: []identitymodel.DataPermission{
		{ObjectKey: "other", Scope: "all_records", Read: true, Write: true},
		{ObjectKey: "invoice", Scope: "", Read: true},
	}}
	if scope := IdentityDataScope(scopeRole, "invoice", false); scope != "none" {
		t.Fatalf("blank read scope=%q", scope)
	}
	if scope := IdentityDataScope(scopeRole, "invoice", true); scope != "none" {
		t.Fatalf("unwritable scope=%q", scope)
	}
	scopeRole.DataPermissions = append(scopeRole.DataPermissions,
		identitymodel.DataPermission{ObjectKey: "invoice", Scope: "department", Read: true},
		identitymodel.DataPermission{ObjectKey: "invoice", Scope: "owned", Read: true},
	)
	if scope := IdentityDataScope(scopeRole, "invoice", false); scope != "custom" {
		t.Fatalf("combined read scope=%q", scope)
	}
	scopeRole.DataPermissions = append(scopeRole.DataPermissions,
		identitymodel.DataPermission{ObjectKey: "invoice", Scope: "all_records", Write: true},
	)
	if scope := IdentityDataScope(scopeRole, "invoice", true); scope != "all_records" {
		t.Fatalf("write scope=%q", scope)
	}
	if scope := IdentityDataScopeForAction(scopeRole, "invoice", "export"); scope != "custom" {
		t.Fatalf("export scope=%q", scope)
	}
}
