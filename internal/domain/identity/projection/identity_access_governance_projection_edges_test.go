package projection

import (
	"testing"
	"time"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAccessReverseIndexEdgeInputs(t *testing.T) {
	index := IdentityBuildAccessReverseIndex(
		[]identitymodel.IdentityRole{{ID: "fallback", Key: " "}, {ID: "known", Key: "role"}},
		[]identitymodel.RoleSchema{{
			Key: "role", Permissions: []string{" ", ".", "object.", "standalone", "namespace.object.update"},
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
	if len(index.ObjectActionRoles["object.update"]) != 1 ||
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
		{UserID: "active", RoleID: "published", Status: string(identitymodel.IdentityStatusActive), WorkforceProfileID: "active-profile"},
		{UserID: "unpublished", RoleID: "unpublished", Status: string(identitymodel.IdentityStatusDisabled)},
		{UserID: "future", RoleID: "published", ValidUntil: future},
		{UserID: "invalid", RoleID: "published", ExpiresAt: &invalid},
		{UserID: "past", RoleID: "published", ValidUntil: past},
		{UserID: "duplicate", RoleID: "published", BindingKey: "member"},
		{UserID: "duplicate", RoleID: "published", BindingKey: "member"},
	}
	report := IdentityBuildGovernanceReports(
		now,
		[]identitymodel.IdentityPermissionDefinition{{Key: " "}, {Key: "orphan"}},
		roles,
		[]identitymodel.RoleSchema{{Key: "published", Permissions: []string{"published.read"}}},
		assignments,
		map[string]bool{"active-profile": true},
	)
	if len(report.AuthorizationDrift) != 1 || len(report.ExpiredEntitlements) != 2 ||
		len(report.UnboundAssignments) != 1 || len(report.OrphanPermissions) != 1 {
		t.Fatalf("report=%+v", report)
	}
	if len(report.RolesWithoutMembers) != 2 {
		t.Fatalf("roles without members=%+v", report.RolesWithoutMembers)
	}
}

func TestIdentityRoleChangeImpactEdgeInputs(t *testing.T) {
	assuranceOTP := &definitionmodel.ActionAssurancePolicy{RequiredMethods: []string{definitionmodel.ActionAssuranceOTP}}
	assuranceApproval := &definitionmodel.ActionAssurancePolicy{RequiredMethods: []string{definitionmodel.ActionAssuranceMakerChecker}}
	impact := IdentityPreviewRoleChange(
		identitymodel.IdentityRoleChangeImpactRequest{Role: identitymodel.RoleSchema{
			Key: "fallback-role",
			Permissions: []string{
				".", "plain", "other.read", "account.update", "account.critical",
				"account.approval", "account.assurance",
			},
		}},
		identitymodel.RoleSchema{Key: "fallback-role", Permissions: []string{"account.old", " "}},
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
			{Key: "wrong-permission", RequiresPermission: "unrelated"},
			{Key: "ordinary", RequiresPermission: "account.update"},
			{Key: "critical", RequiresPermission: "account.critical", RiskLevel: "critical"},
			{Key: "approval", RequiresPermission: "account.approval", AssurancePolicy: assuranceApproval},
			{Key: "assurance", RequiresPermission: "account.assurance", AssurancePolicy: assuranceOTP},
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
