package projection

import (
	"reflect"
	"testing"
	"time"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAccessReverseIndexAndGovernanceReportsAreDeterministic(t *testing.T) {
	expires := "2026-07-24T00:00:00Z"
	roles := []identitymodel.IdentityRole{
		{ID: "reader-id", Key: "reader"},
		{ID: "empty-id", Key: "empty"},
	}
	definitions := []identitymodel.RoleSchema{{Key: "reader", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "order.read", "order.export")}}
	assignments := []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user-b", RoleID: "reader-id", BindingKey: "member"},
		{UserID: "user-a", RoleID: "reader-id"},
		{UserID: "expired", RoleID: "reader-id", ExpiresAt: &expires},
		{UserID: "drift", RoleID: "missing"},
	}
	index := IdentityBuildAccessReverseIndex(roles, definitions, assignments)
	if !reflect.DeepEqual(index.UserRoles["user-a"], []string{"reader"}) ||
		!reflect.DeepEqual(index.PermissionRoles["order.read"], []string{"reader"}) ||
		!reflect.DeepEqual(index.ObjectActionRoles["order.export"], []string{"reader"}) {
		t.Fatalf("reverse index=%#v", index)
	}
	reports := IdentityBuildGovernanceReports(
		time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC),
		[]identitymodel.IdentityPermissionDefinition{{Key: "order.read", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true}, {Key: "order.export", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true}, {Key: "unused.permission", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true}},
		roles, definitions, assignments,
	)
	if !reflect.DeepEqual(reports.OrphanPermissions, []string{"unused.permission"}) ||
		!reflect.DeepEqual(reports.RolesWithoutMembers, []string{"empty"}) ||
		len(reports.ExpiredEntitlements) != 1 || len(reports.UnboundAssignments) != 1 ||
		!reflect.DeepEqual(reports.AuthorizationDrift, []string{"assignment:drift:missing:unknown_role"}) {
		t.Fatalf("governance reports=%#v", reports)
	}
}

func TestIdentityRoleChangeImpactCoversUsersProfilesSensitiveFieldsAndHighRiskActions(t *testing.T) {
	current := identitymodel.RoleSchema{Key: "operator", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "order.read")}
	next := identitymodel.RoleSchema{Key: "operator", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "order.read", "order.refund")}
	impact := IdentityPreviewRoleChange(
		identitymodel.IdentityRoleChangeImpactRequest{RoleKey: "operator", Role: next},
		current,
		identitymodel.IdentityRole{ID: "operator-id", Key: "operator"},
		[]identitymodel.IdentityUserRoleAssignment{
			{UserID: "employee", RoleID: "operator-id"},
			{UserID: "member", RoleID: "operator-id", BindingKey: "member"},
		},
		[]definitionmodel.ObjectSchema{{Key: "order", Fields: []definitionmodel.FieldSchema{{Key: "payment_token", Config: map[string]any{"sensitivity": "credential"}}}}},
		[]definitionmodel.ActionSchema{{Key: "order.refund", RiskLevel: "high"}},
	)
	if impact.AffectedUserCount != 2 ||
		!reflect.DeepEqual(impact.ProfileTypes, []string{"account", "business_profile:member"}) ||
		!reflect.DeepEqual(impact.AddedPermissions, []string{"order.refund"}) ||
		!reflect.DeepEqual(impact.SensitiveFields, []string{"order.payment_token"}) ||
		!reflect.DeepEqual(impact.HighRiskCapabilities, []string{"order.refund"}) {
		t.Fatalf("impact=%#v", impact)
	}
}
