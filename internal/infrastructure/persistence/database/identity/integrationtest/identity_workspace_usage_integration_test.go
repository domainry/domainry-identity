package identity_test

import (
	"fmt"
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestWorkspaceIdentityUsageStoreGroupsOnlyBoundedIdentityAccountDimensions(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "workspace-usage.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	users := []struct {
		workspaceID string
		id          string
		accountType identitymodel.IdentityAccountType
		status      identitymodel.IdentityStatus
	}{
		{"workspace-a", "a-human-active-1", identitymodel.IdentityAccountHuman, identitymodel.IdentityStatusActive},
		{"workspace-a", "a-human-active-2", identitymodel.IdentityAccountHuman, identitymodel.IdentityStatusActive},
		{"workspace-a", "a-human-disabled", identitymodel.IdentityAccountHuman, identitymodel.IdentityStatusDisabled},
		{"workspace-a", "a-human-deleted", identitymodel.IdentityAccountHuman, identitymodel.IdentityStatusDeleted},
		{"workspace-a", "a-service-active", identitymodel.IdentityAccountService, identitymodel.IdentityStatusActive},
		{"workspace-a", "a-service-disabled", identitymodel.IdentityAccountService, identitymodel.IdentityStatusDisabled},
		{"workspace-a", "a-automation-deleted", identitymodel.IdentityAccountAutomation, identitymodel.IdentityStatusDeleted},
		{"workspace-b", "b-automation-active", identitymodel.IdentityAccountAutomation, identitymodel.IdentityStatusActive},
		{"workspace-b", "b-human-active", identitymodel.IdentityAccountHuman, identitymodel.IdentityStatusActive},
		{"workspace-inactive", "inactive-human", identitymodel.IdentityAccountHuman, identitymodel.IdentityStatusActive},
	}
	for _, record := range users {
		if err := repository.UpsertIdentityUser(t.Context(), record.workspaceID, identitymodel.IdentityUser{
			ID: record.id, Name: record.id, Email: record.id + "@example.test", AccountType: record.accountType,
			Status: record.status, Version: 1, ReportingPath: "/" + record.id,
		}); err != nil {
			t.Fatalf("insert %s: %v", record.id, err)
		}
	}
	assignments := []struct {
		workspaceID string
		userID      string
		roleID      string
		status      string
	}{
		{"workspace-a", "a-human-active-1", "role-admin", "active"},
		{"workspace-a", "a-human-active-1", "role-staff", "active"},
		{"workspace-a", "a-human-active-2", "role-revoked", "revoked"},
		{"workspace-a", "a-human-disabled", "role-disabled-user", "active"},
		{"workspace-a", "a-human-deleted", "role-deleted-user", "active"},
		{"workspace-a", "a-service-active", "role-service", "active"},
		{"workspace-b", "b-human-active", "role-viewer", "active"},
		{"workspace-b", "b-automation-active", "role-automation", "active"},
		{"workspace-inactive", "inactive-human", "role-outside", "active"},
	}
	for _, assignment := range assignments {
		if err := repository.AssignIdentityUserRole(t.Context(), assignment.workspaceID, identitymodel.IdentityUserRoleAssignment{
			UserID: assignment.userID, RoleID: assignment.roleID, Status: assignment.status,
		}); err != nil {
			t.Fatalf("assign %s/%s: %v", assignment.userID, assignment.roleID, err)
		}
	}

	// This foreign application table intentionally contains unrelated people.
	// It is test fixture setup, not Identity persistence; the usage repository
	// must neither read it nor infer an account count from it.
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE employee_profile (workspace_id TEXT NOT NULL, id TEXT PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 7; index++ {
		if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO employee_profile (workspace_id, id, name) VALUES (?, ?, ?)`, "workspace-a", fmt.Sprintf("employee-%d", index), "Unrelated Employee"); err != nil {
			t.Fatal(err)
		}
	}

	groups, err := repository.CountIdentityWorkspaceUsage(t.Context(), []string{"workspace-a", "workspace-b"})
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string]int64, len(groups))
	for _, group := range groups {
		actual[group.WorkspaceID+"/"+string(group.AccountType)+"/"+string(group.Status)] = group.Count
	}
	expected := map[string]int64{
		"workspace-a/human/active":       2,
		"workspace-a/human/disabled":     1,
		"workspace-a/human/deleted":      1,
		"workspace-a/service/active":     1,
		"workspace-a/service/disabled":   1,
		"workspace-a/automation/deleted": 1,
		"workspace-b/automation/active":  1,
		"workspace-b/human/active":       1,
	}
	if len(actual) != len(expected) {
		t.Fatalf("groups=%v want=%v", actual, expected)
	}
	for key, count := range expected {
		if actual[key] != count {
			t.Fatalf("group %s=%d want=%d; all=%v", key, actual[key], count, actual)
		}
	}
	for key := range actual {
		if key == "workspace-inactive/human/active" {
			t.Fatalf("unselected Workspace leaked into aggregate: %v", actual)
		}
	}
	activeRoleCounts, err := repository.CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(t.Context(), []string{"workspace-a", "workspace-b"})
	if err != nil {
		t.Fatal(err)
	}
	actualActiveRoles := make(map[string]int64, len(activeRoleCounts))
	for _, count := range activeRoleCounts {
		actualActiveRoles[count.WorkspaceID] = count.Count
	}
	if len(actualActiveRoles) != 2 || actualActiveRoles["workspace-a"] != 1 || actualActiveRoles["workspace-b"] != 1 {
		t.Fatalf("distinct active human role counts=%v want workspace-a=1 workspace-b=1", actualActiveRoles)
	}

	for _, indexName := range []string{"idx_identity_users_workspace_active_role_usage", "idx_identity_user_roles_workspace_active_usage"} {
		var found int
		if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, indexName).Scan(&found); err != nil || found != 1 {
			t.Fatalf("supporting index %q found=%d err=%v", indexName, found, err)
		}
	}
}

func TestWorkspaceIdentityUsageStoreEnforcesHardLimitAndUniqueWorkspaceSet(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "workspace-usage-limits.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]string, 101)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("workspace-%03d", index)
	}
	if _, err := repository.CountIdentityWorkspaceUsage(t.Context(), tooMany); err == nil {
		t.Fatal("aggregate accepted more than the hard Workspace page limit")
	}
	if _, err := repository.CountIdentityWorkspaceUsage(t.Context(), []string{"workspace-a", "workspace-a"}); err == nil {
		t.Fatal("aggregate accepted a duplicate Workspace scope")
	}
	if _, err := repository.CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(t.Context(), tooMany); err == nil {
		t.Fatal("active human role aggregate accepted more than the hard Workspace page limit")
	}
	if _, err := repository.CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(t.Context(), []string{"workspace-a", "workspace-a"}); err == nil {
		t.Fatal("active human role aggregate accepted a duplicate Workspace scope")
	}
}
