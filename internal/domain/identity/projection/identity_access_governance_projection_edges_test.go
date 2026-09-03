package projection

import (
	"reflect"
	"testing"
	"time"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAccessReverseIndexEdgeInputs(t *testing.T) {
	index := IdentityBuildAccessReverseIndex(
		[]identitymodel.IdentityRole{{ID: "fallback", Key: " "}, {ID: "known", Key: "role"}},
		[]identitymodel.RoleSchema{{
			Key: "role", Permissions: []identitymodel.RolePermission{
				{PermissionKey: " ", DataScope: identitymodel.IdentityDataScopeAll},
				{PermissionKey: ".", DataScope: identitymodel.IdentityDataScopeAll},
				{PermissionKey: "object.", DataScope: identitymodel.IdentityDataScopeAll},
				{PermissionKey: "standalone", DataScope: identitymodel.IdentityDataScopeAll},
				{PermissionKey: "namespace.object.update", DataScope: identitymodel.IdentityDataScopeAll},
			},
		}},
		[]identitymodel.IdentityUserRoleAssignment{
			{UserID: "inactive", RoleID: "known", Status: string(identitymodel.IdentityStatusDisabled)},
			{UserID: "fallback-user", RoleID: "fallback", Status: string(identitymodel.IdentityStatusActive)},
			{UserID: "unknown", RoleID: "missing"},
		},
	)
	if len(index.UserRoles["inactive"]) != 0 || len(index.UserRoles["unknown"]) != 0 ||
		len(index.UserRoles["fallback-user"]) != 1 || index.UserRoles["fallback-user"][0] != "fallback" {
		t.Fatalf("user roles=%+v", index.UserRoles)
	}
	if len(index.ObjectActionRoles["namespace.object.update"]) != 1 ||
		len(index.ObjectActionRoles["standalone"]) != 0 {
		t.Fatalf("object action roles=%+v", index.ObjectActionRoles)
	}
}

func TestIdentityGovernanceReportsEdgeInputs(t *testing.T) {
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour).Format(time.RFC3339)
	past := now.Add(-time.Hour).Format(time.RFC3339)
	invalid := "invalid"
	roles := []identitymodel.IdentityRole{
		{ID: "published", Key: "published"},
		{ID: "unpublished", Key: "unpublished"},
		{ID: "fallback", Key: " "},
	}
	assignments := []identitymodel.IdentityUserRoleAssignment{
		{UserID: "active", RoleID: "published", Status: string(identitymodel.IdentityStatusActive)},
		{UserID: "unpublished", RoleID: "unpublished", Status: string(identitymodel.IdentityStatusDisabled)},
		{UserID: "future", RoleID: "published", ValidUntil: future},
		{UserID: "invalid", RoleID: "published", ExpiresAt: &invalid},
		{UserID: "past", RoleID: "published", ValidUntil: past},
		{UserID: "duplicate", RoleID: "published", BindingKey: "member"},
		{UserID: "duplicate", RoleID: "published", BindingKey: "member"},
	}
	report := IdentityBuildGovernanceReports(
		now,
		[]identitymodel.IdentityPermissionDefinition{{Key: " "}, {Key: "orphan", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true}, {Key: "published.read", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true}},
		roles,
		[]identitymodel.RoleSchema{{Key: "published", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "published.read")}},
		assignments,
	)
	if len(report.AuthorizationDrift) != 1 || len(report.ExpiredEntitlements) != 2 ||
		len(report.UnboundAssignments) != 1 || len(report.OrphanPermissions) != 1 {
		t.Fatalf("report=%+v", report)
	}
	if len(report.RolesWithoutMembers) != 2 {
		t.Fatalf("roles without members=%+v", report.RolesWithoutMembers)
	}
}

func TestIdentityGovernanceReportsPermissionDefinitionDrift(t *testing.T) {
	report := IdentityBuildGovernanceReports(
		time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC),
		[]identitymodel.IdentityPermissionDefinition{
			{Key: "active", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true},
			{Key: "disabled", DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: false},
			{Key: "retired", DefinitionStatus: identitymodel.IdentityPermissionDefinitionRetired, Enabled: true},
		},
		nil,
		[]identitymodel.RoleSchema{{Key: "role", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "active", "disabled", "retired", "unknown")}},
		nil,
	)
	want := []string{
		"role:role:permission:disabled:disabled",
		"role:role:permission:retired:retired",
		"role:role:permission:unknown:unknown",
	}
	if !reflect.DeepEqual(report.AuthorizationDrift, want) {
		t.Fatalf("authorization drift=%#v want=%#v", report.AuthorizationDrift, want)
	}
}

func TestIdentityRoleChangeImpactEdgeInputs(t *testing.T) {
	assuranceOTP := &definitionmodel.ActionAssurancePolicy{RequiredMethods: []string{definitionmodel.ActionAssuranceOTP}}
	assuranceApproval := &definitionmodel.ActionAssurancePolicy{RequiredMethods: []string{definitionmodel.ActionAssuranceMakerChecker}}
	impact := IdentityPreviewRoleChange(
		identitymodel.IdentityRoleChangeImpactRequest{Role: identitymodel.RoleSchema{
			Key: "fallback-role",
			Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
				".", "plain", "other.read", "account.update", "account.critical",
				"account.approval", "account.assurance",
			),
		}},
		identitymodel.RoleSchema{Key: "fallback-role", Permissions: []identitymodel.RolePermission{
			{PermissionKey: "account.old", DataScope: identitymodel.IdentityDataScopeAll},
			{PermissionKey: " ", DataScope: identitymodel.IdentityDataScopeAll},
		}},
		identitymodel.IdentityRole{ID: "role-id"},
		[]identitymodel.IdentityUserRoleAssignment{
			{UserID: "wrong", RoleID: "other"},
			{UserID: "inactive", RoleID: "role-id", Status: string(identitymodel.IdentityStatusDisabled)},
			{UserID: "account", RoleID: "role-id", Status: string(identitymodel.IdentityStatusActive)},
		},
		[]definitionmodel.ObjectSchema{
			{Key: "other", Fields: []definitionmodel.FieldSchema{{Key: "ignored"}}},
			{Key: "account", Fields: []definitionmodel.FieldSchema{{Key: "ordinary"}, {Key: "secret", Config: map[string]any{"sensitive": true}}}},
		},
		[]definitionmodel.ActionSchema{
			{Key: "unrelated"},
			{Key: "account.update"},
			{Key: "account.critical", RiskLevel: "critical"},
			{Key: "account.approval", AssurancePolicy: assuranceApproval},
			{Key: "account.assurance", AssurancePolicy: assuranceOTP},
		},
	)
	if impact.RoleKey != "fallback-role" || impact.AffectedUserCount != 1 ||
		len(impact.ProfileTypes) != 1 || impact.ProfileTypes[0] != "account" {
		t.Fatalf("impact identity=%+v", impact)
	}
	if len(impact.HighRiskCapabilities) != 3 || len(impact.SensitiveFields) != 1 {
		t.Fatalf("impact governance=%+v", impact)
	}
}

func TestIdentityAccessGovernanceValueHelperEdges(t *testing.T) {
	now := time.Now().UTC()
	if identityProjectionAssignmentExpired(identitymodel.IdentityUserRoleAssignment{ValidUntil: now.Add(time.Hour).Format(time.RFC3339)}, now) {
		t.Fatal("future assignment treated as expired")
	}
	if identityProjectionAssignmentExpired(identitymodel.IdentityUserRoleAssignment{}, now) {
		t.Fatal("assignment without expiry treated as expired")
	}
	values := identityProjectionUniqueAssignments([]identitymodel.IdentityUserRoleAssignment{
		{UserID: "user", RoleID: "role"},
		{UserID: "user", RoleID: "role"},
	})
	if len(values) != 1 {
		t.Fatalf("unique assignments=%+v", values)
	}
	if difference := identityProjectionStringDifference([]string{" ", "kept", "kept"}, []string{"removed"}); len(difference) != 1 || difference[0] != "kept" {
		t.Fatalf("difference=%+v", difference)
	}
}
