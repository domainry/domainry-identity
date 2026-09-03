package service

import (
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestPrepareEntitlementBatchValidatesFinalConflictsAndTreatsWorkspaceCapabilityAsOrdinaryGrant(t *testing.T) {
	repository, service := identityRolesFixture()
	repository.users = append(repository.users, identitymodel.IdentityUser{ID: "admin-2", Status: identitymodel.IdentityStatusActive})
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, ConflictRoleKeys: []string{"viewer"}},
		{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
		{Key: "admin", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identityTestRolePermissions("identity.roles.list")},
		{Key: "owner", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identityTestRolePermissions("identity.roles.list")},
	})
	actor := identitymodel.Principal{Known: true, UserID: "admin-2", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityEntitlementsBatchPermission)}}
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{
		{Operation: "grant", UserID: "user-1", RoleID: "member-id"},
		{Operation: "grant", UserID: "user-1", RoleID: "viewer-id"},
	}, actor); apperror.CodeOf(err) != "backend.identity.role_conflict" {
		t.Fatalf("batch conflict error=%v", err)
	}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-1", RoleID: "admin-id", Status: "active"},
		{UserID: "admin-2", RoleID: "owner-id", Status: "active"},
	}
	items, assignments, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{
		{Operation: "revoke", UserID: "user-1", RoleID: "admin-id", Reason: "rotation"},
	}, actor)
	if err != nil || len(items) != 1 || len(assignments) != 1 || assignments[0].Status != "revoked" {
		t.Fatalf("cross-role administrator preservation items=%#v assignments=%#v err=%v", items, assignments, err)
	}
	repository.assignments = repository.assignments[:1]
	items, assignments, err = service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{
		{Operation: "revoke", UserID: "user-1", RoleID: "admin-id", Reason: "unsafe"},
	}, actor)
	if err != nil || len(items) != 1 || len(assignments) != 1 || assignments[0].Status != "revoked" {
		t.Fatalf("ordinary exact workspace capability revocation items=%#v assignments=%#v err=%v", items, assignments, err)
	}
}

func TestPrepareEntitlementBatchEnforcesGrantCeilingAndSelfGrant(t *testing.T) {
	_, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "admin", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
		{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentManual, RiskLevel: identitymodel.IdentityRoleRiskElevated},
	})
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{
		{Operation: "grant", UserID: "user-1", RoleID: "admin-id"},
	}, identitymodel.Principal{Known: true, UserID: "user-1", Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"*"}, Permissions: identityTestRolePermissions(identitycontract.IdentityEntitlementsBatchPermission)}}); apperror.CodeOf(err) != "backend.identity.privileged_self_grant_denied" {
		t.Fatalf("self grant error=%v", err)
	}
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{
		{Operation: "grant", UserID: "user-1", RoleID: "viewer-id"},
	}, identitymodel.Principal{Known: true, UserID: "grantor", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityEntitlementsBatchPermission)}}); apperror.CodeOf(err) != "backend.identity.role_grant_ceiling_exceeded" {
		t.Fatalf("grant ceiling error=%v", err)
	}
}

func TestPrepareEntitlementBatchRejectsActorShapeEmptyInputAndRepositoryFailures(t *testing.T) {
	repository, service := identityRolesFixture()
	valid := []identitymodel.IdentityEntitlementBatchItem{{
		Operation: identitymodel.IdentityEntitlementOperationGrant,
		UserID:    "user-1",
		RoleID:    "member-id",
	}}
	for name, actor := range map[string]identitymodel.Principal{
		"unknown":    {Known: false, UserID: "actor"},
		"blank-user": {Known: true, UserID: " "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), valid, actor); apperror.CodeOf(err) != "backend.identity.entitlement_actor_required" {
				t.Fatalf("actor error=%v", err)
			}
		})
	}
	actor := identitymodel.Principal{Known: true, UserID: "actor", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityEntitlementsBatchPermission)}}
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), nil, actor); apperror.CodeOf(err) != "backend.identity.entitlement_batch_empty" {
		t.Fatalf("empty batch error=%v", err)
	}
	repository.listAssignmentsErr = errIdentityRolesRepository
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), valid, actor); !errors.Is(err, errIdentityRolesRepository) {
		t.Fatalf("assignment list error=%v", err)
	}
	repository.listAssignmentsErr = nil
	repository.listRolesErr = errIdentityRolesRepository
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), valid, actor); !errors.Is(err, errIdentityRolesRepository) {
		t.Fatalf("role list error=%v", err)
	}
}

func TestPrepareEntitlementBatchRejectsInvalidItemsMissingRolesAndOperations(t *testing.T) {
	_, service := identityRolesFixture()
	actor := identitymodel.Principal{Known: true, UserID: "actor", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityEntitlementsBatchPermission)}}
	cases := []struct {
		name  string
		items []identitymodel.IdentityEntitlementBatchItem
		code  string
	}{
		{
			name: "blank-user",
			items: []identitymodel.IdentityEntitlementBatchItem{{
				Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: " ", RoleID: "member-id",
			}},
			code: "backend.identity.entitlement_batch_item_invalid",
		},
		{
			name: "blank-role",
			items: []identitymodel.IdentityEntitlementBatchItem{{
				Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: "user-1", RoleID: " ",
			}},
			code: "backend.identity.entitlement_batch_item_invalid",
		},
		{
			name: "duplicate",
			items: []identitymodel.IdentityEntitlementBatchItem{
				{Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: "user-1", RoleID: "member-id"},
				{Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: " user-1 ", RoleID: " member-id "},
			},
			code: "backend.identity.entitlement_batch_item_invalid",
		},
		{
			name: "missing-role",
			items: []identitymodel.IdentityEntitlementBatchItem{{
				Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: "user-1", RoleID: "missing",
			}},
			code: "backend.identity.role_not_found",
		},
		{
			name: "unknown-operation",
			items: []identitymodel.IdentityEntitlementBatchItem{{
				Operation: "replace", UserID: "user-1", RoleID: "member-id",
			}},
			code: "backend.identity.entitlement_batch_operation_invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), tc.items, actor); apperror.CodeOf(err) != tc.code {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPrepareEntitlementBatchRejectsSystemManagedMissingAndInactiveRevocations(t *testing.T) {
	repository, service := identityRolesFixture()
	service.ReplaceRoleDefinitions([]identitymodel.RoleSchema{
		{Key: "member", AssignmentMode: identitymodel.IdentityRoleAssignmentSystemManaged},
		{Key: "viewer", AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	})
	actor := identitymodel.Principal{Known: true, UserID: "actor", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityEntitlementsBatchPermission)}}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{
		UserID: "user-1", RoleID: "member-id", Status: "active",
	}}
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{{
		Operation: identitymodel.IdentityEntitlementOperationGrant, UserID: "user-1", RoleID: "member-id",
	}}, actor); apperror.CodeOf(err) != "backend.identity.system_managed_role_assignment_denied" {
		t.Fatalf("system-managed grant error=%v", err)
	}
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{{
		Operation: identitymodel.IdentityEntitlementOperationRevoke, UserID: "user-1", RoleID: "member-id",
	}}, actor); apperror.CodeOf(err) != "backend.identity.system_managed_role_assignment_denied" {
		t.Fatalf("system-managed revoke error=%v", err)
	}

	repository.assignments = nil
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{{
		Operation: identitymodel.IdentityEntitlementOperationRevoke, UserID: "user-1", RoleID: "viewer-id",
	}}, actor); apperror.CodeOf(err) != "backend.identity.entitlement_not_active" {
		t.Fatalf("missing revoke error=%v", err)
	}
	repository.assignments = []identitymodel.IdentityUserRoleAssignment{{
		UserID: "user-1", RoleID: "viewer-id", Status: "revoked",
	}}
	if _, _, err := service.PrepareIdentityEntitlementBatch(t.Context(), []identitymodel.IdentityEntitlementBatchItem{{
		Operation: identitymodel.IdentityEntitlementOperationRevoke, UserID: "user-1", RoleID: "viewer-id",
	}}, actor); apperror.CodeOf(err) != "backend.identity.entitlement_not_active" {
		t.Fatalf("inactive revoke error=%v", err)
	}
}

func TestIdentityEntitlementGrantCeilingAndFinalStateRemainingOutcomes(t *testing.T) {
	actor := identitymodel.Principal{
		Known: true, UserID: "grantor",
		Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"elevated"}},
	}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "recipient"}
	if err := validateIdentityEntitlementGrantCeiling(actor, assignment, identitymodel.RoleSchema{
		Key: "privileged", RiskLevel: identitymodel.IdentityRoleRiskPrivileged,
	}); apperror.CodeOf(err) != "backend.identity.role_grant_ceiling_exceeded" {
		t.Fatalf("privileged other-user ceiling error=%v", err)
	}
	if err := validateIdentityEntitlementGrantCeiling(actor, assignment, identitymodel.RoleSchema{
		Key: "elevated", RiskLevel: identitymodel.IdentityRoleRiskElevated,
	}); err != nil {
		t.Fatalf("explicit grantable role rejected: %v", err)
	}
	if err := validateIdentityEntitlementGrantCeiling(identitymodel.Principal{
		Known: true, UserID: "grantor",
		Role: identitymodel.RoleSchema{GrantableRoleKeys: []string{"*"}},
	}, assignment, identitymodel.RoleSchema{
		Key: "elevated", RiskLevel: identitymodel.IdentityRoleRiskElevated,
	}); err != nil {
		t.Fatalf("wildcard grantable role rejected: %v", err)
	}

	now := time.Now().UTC()
	definitions := map[string]identitymodel.RoleSchema{
		"left":  {Key: "left"},
		"right": {Key: "right", ConflictRoleKeys: []string{"left"}},
	}
	final := map[string]identitymodel.IdentityUserRoleAssignment{
		"missing": {UserID: "user", RoleID: "missing", Status: "active"},
		"left":    {UserID: "user", RoleID: "left", Status: "active"},
		"right":   {UserID: "user", RoleID: "right", Status: "active"},
	}
	if err := validateIdentityEntitlementFinalState(final, definitions, now); apperror.CodeOf(err) != "backend.identity.role_conflict" {
		t.Fatalf("reverse conflict error=%v", err)
	}
}
