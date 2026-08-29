package identity

import (
	"database/sql/driver"
	"fmt"
	"testing"
)

func identityDirectoryRoleColumns() []string {
	return []string{
		"user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status",
		"valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at",
		"revoke_reason", "expires_at", "created_at", "updated_at",
	}
}

func identityDirectoryRoleRow() []driver.Value {
	return []driver.Value{
		"user", "role", "workforce", "binding", "profile", "manual", "active",
		"from", "until", "admin", "reason", nil, nil, nil, nil, "created", "updated",
	}
}

func identityDirectoryBindingColumns() []string {
	return []string{
		"workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id",
		"status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at",
	}
}

func identityDirectoryBindingRow() []driver.Value {
	return []driver.Value{
		"workspace", "binding", "member", "profile", "user",
		"active", "email", "token", int64(1), "created", "updated",
	}
}

func TestListIdentityUserDirectoryFactsInputAndQueryFailures(t *testing.T) {
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if facts, err := store.ListIdentityUserDirectoryFacts(t.Context(), "", []string{"user"}); err == nil || facts.RoleAssignments == nil {
		t.Fatalf("blank workspace facts=%#v error=%v", facts, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if facts, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", nil); err != nil ||
		facts.RoleAssignments == nil || facts.WorkforceProfiles == nil || facts.ProfileBindings == nil {
		t.Fatalf("empty IDs facts=%#v error=%v", facts, err)
	}
	closeDB()

	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{
			queryFailAt: 2, failure: errProfileBindingSQL,
			querySteps: []identitySQLQueryStep{{}},
		},
		{
			queryFailAt: 3, failure: errProfileBindingSQL,
			querySteps: []identitySQLQueryStep{{}, {}},
		},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", []string{"user"}); err == nil {
			t.Fatal("directory query failure ignored")
		}
		closeDB()
	}
}

func TestListIdentityUserDirectoryFactsRoleFailures(t *testing.T) {
	for _, roleStep := range []identitySQLQueryStep{
		{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
		{columns: identityDirectoryRoleColumns(), nextErr: errProfileBindingSQL},
	} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{roleStep}})
		if _, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", []string{"user"}); err == nil {
			t.Fatal("role row failure ignored")
		}
		closeDB()
	}
}

func TestListIdentityUserDirectoryFactsProfileFailures(t *testing.T) {
	for _, profileStep := range []identitySQLQueryStep{
		{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
		{
			columns: []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"},
			nextErr: errProfileBindingSQL,
		},
	} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
			{},
			profileStep,
		}})
		if _, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", []string{"user"}); err == nil {
			t.Fatal("profile row failure ignored")
		}
		closeDB()
	}
}

func TestListIdentityUserDirectoryFactsBindingFailuresAndSuccess(t *testing.T) {
	store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{},
		{},
		{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
	}})
	if _, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", []string{"user"}); err == nil {
		t.Fatal("binding scan failure ignored")
	}
	closeDB()

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: identityDirectoryRoleColumns(), rows: [][]driver.Value{identityDirectoryRoleRow()}},
		{
			columns: []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"},
			rows:    [][]driver.Value{workforceProfileRow()},
		},
		{columns: identityDirectoryBindingColumns(), rows: [][]driver.Value{identityDirectoryBindingRow()}},
	}})
	facts, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", []string{"user", "other"})
	if err != nil || len(facts.RoleAssignments) != 1 || len(facts.WorkforceProfiles) != 1 || len(facts.ProfileBindings) != 1 {
		t.Fatalf("facts=%#v error=%v", facts, err)
	}
	if facts.RoleAssignments[0].WorkforceProfileID != "workforce" ||
		facts.RoleAssignments[0].ExpiresAt != nil || facts.ProfileBindings[0].IdentityUserID != "user" {
		t.Fatalf("facts=%#v", facts)
	}
	closeDB()
}

func TestIdentityUserDirectoryFactsBatchesByParameterBudget(t *testing.T) {
	state := &identitySQLState{}
	store, closeDB := scriptedSQLIdentity(state)
	defer closeDB()
	userIDs := make([]string, identityDirectoryBatchMaxItems+1)
	for index := range userIDs {
		userIDs[index] = fmt.Sprintf("user-%04d", index)
	}
	if _, err := store.ListIdentityUserDirectoryFacts(t.Context(), "workspace", userIDs); err != nil {
		t.Fatal(err)
	}
	if state.queryCount != 6 {
		t.Fatalf("query count=%d, want 6 for two batches across three fact owners", state.queryCount)
	}
}
