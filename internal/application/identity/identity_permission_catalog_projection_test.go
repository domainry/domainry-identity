package identity

import (
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPermissionsExposeBusinessCRUDAndSkipSystemObjects(t *testing.T) {
	permissions := IdentityPermissionsFromRoles(nil, []definitionmodel.ObjectSchema{
		{Key: "customer", Name: "Customer"},
		{Key: "job_run", Name: "Job Run", Config: map[string]any{"system_object": true}},
	}, "en-US")
	keys := map[string]bool{}
	for _, permission := range permissions {
		keys[permission.Key] = true
	}
	for _, key := range []string{"customer.create", "customer.read", "customer.update", "customer.delete"} {
		if !keys[key] {
			t.Fatalf("expected domain CRUD permission %s in %#v", key, permissions)
		}
	}
	for _, key := range []string{"job_run.create", "job_run.read", "job_run.update", "job_run.delete"} {
		if keys[key] {
			t.Fatalf("system object permission %s should not be generated", key)
		}
	}
}

func TestActionDerivedPermissionExistsBeforeRoleGrantAndPublishesGovernanceMetadata(t *testing.T) {
	action := definitionmodel.ActionSchema{
		Key: "refund.approve", ObjectKey: "refund", Label: "Approve refund", Kind: "record_operation", RequiresPermission: "refund.approve",
		AssurancePolicy: &definitionmodel.ActionAssurancePolicy{RequiredMethods: []string{definitionmodel.ActionAssuranceOTP, definitionmodel.ActionAssuranceWorkflowApproval}},
	}
	permissions := IdentityPermissionsFromRuntime(
		nil,
		[]definitionmodel.ObjectSchema{{Key: "refund", Name: "Refund"}},
		[]definitionmodel.ActionSchema{action}, "en-US",
	)
	count := 0
	var derived identitymodel.IdentityPermissionDefinition
	for _, permission := range permissions {
		if permission.Key == action.RequiresPermission {
			count++
			derived = permission
		}
	}
	if count != 1 || derived.SourceType != "business_action" || derived.SourceActionKey != action.Key || derived.ObjectKey != action.ObjectKey || derived.ActionLabel != action.Label || derived.AuthorizationStrategy != "dedicated_permission" || derived.RiskLevel != "critical" || !derived.ApprovalRequired || derived.LifecycleStatus != "active" || len(derived.AssuranceRequired) != 2 || len(derived.ActionUsages) != 1 || derived.ActionUsages[0].ActionKey != action.Key {
		t.Fatalf("derived permission=%#v count=%d", derived, count)
	}

	inherited := IdentityPermissionsFromRuntime(nil, []definitionmodel.ObjectSchema{{Key: "order", Name: "Order"}}, []definitionmodel.ActionSchema{
		{Key: "order.view", ObjectKey: "order", Label: "View", Kind: "object_operation", RequiresPermission: "order.read"},
		{Key: "order.preview", ObjectKey: "order", Label: "Preview", Kind: "object_operation", RequiresPermission: "order.read"},
	}, "en-US")
	for _, permission := range inherited {
		if permission.Key == "order.read" && permission.SourceType != "" {
			t.Fatalf("object CRUD permission must remain object-owned: %#v", permission)
		}
		if permission.Key == "order.read" && (len(permission.ActionUsages) != 2 || permission.ActionUsages[0].AuthorizationStrategy != "inherit_object_permission" || permission.ActionUsages[1].ActionKey != "order.preview") {
			t.Fatalf("object CRUD permission must expose every inheriting Action usage: %#v", permission)
		}
	}
}
