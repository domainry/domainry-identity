package identity

import (
	"database/sql/driver"
	"fmt"
	"testing"
)

func identityProjectionRoleColumns() []string {
	return []string{
		"user_id", "role_id", "binding_key", "profile_id", "source", "status",
		"valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at",
		"revoke_reason", "expires_at", "created_at", "updated_at",
	}
}

func identityProjectionRoleRow() []driver.Value {
	return []driver.Value{
		"user", "role", "binding", "profile", "manual", "active",
		int64(1), int64(2), "admin", "reason", nil, int64(0), nil, int64(0), int64(3), int64(4),
	}
}

func identityProjectionBindingColumns() []string {
	return []string{
		"workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id",
		"status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at",
	}
}

func identityProjectionBindingRow() []driver.Value {
	return []driver.Value{
		"workspace", "binding", "member", "profile", "user",
		"active", "email", "token", int64(1), int64(1), int64(2),
	}
}

func TestListIdentityUserProjectionFactsInputAndQueryFailures(t *testing.T) {
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if facts, err := store.ListIdentityUserProjectionFacts(t.Context(), "", []string{"user"}); err == nil || facts.RoleAssignments == nil {
		t.Fatalf("blank workspace facts=%#v error=%v", facts, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if facts, err := store.ListIdentityUserProjectionFacts(t.Context(), "workspace", nil); err != nil ||
		facts.RoleAssignments == nil || facts.ProfileBindings == nil {
		t.Fatalf("empty IDs facts=%#v error=%v", facts, err)
	}
	closeDB()

	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{
			queryFailAt: 2, failure: errProfileBindingSQL,
			querySteps: []identitySQLQueryStep{{}},
		},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, err := store.ListIdentityUserProjectionFacts(t.Context(), "workspace", []string{"user"}); err == nil {
			t.Fatal("projection query failure ignored")
		}
		closeDB()
	}
}

func TestListIdentityUserProjectionFactsRoleFailures(t *testing.T) {
	for _, roleStep := range []identitySQLQueryStep{
		{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
		{columns: identityProjectionRoleColumns(), nextErr: errProfileBindingSQL},
	} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{roleStep}})
		if _, err := store.ListIdentityUserProjectionFacts(t.Context(), "workspace", []string{"user"}); err == nil {
			t.Fatal("role row failure ignored")
		}
		closeDB()
	}
}

func TestListIdentityUserProjectionFactsBindingFailuresAndSuccess(t *testing.T) {
	store, closeDB := scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{},
		{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
	}})
	if _, err := store.ListIdentityUserProjectionFacts(t.Context(), "workspace", []string{"user"}); err == nil {
		t.Fatal("binding scan failure ignored")
	}
	closeDB()

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: identityProjectionRoleColumns(), rows: [][]driver.Value{identityProjectionRoleRow()}},
		{columns: identityProjectionBindingColumns(), rows: [][]driver.Value{identityProjectionBindingRow()}},
	}})
	facts, err := store.ListIdentityUserProjectionFacts(t.Context(), "workspace", []string{"user", "other"})
	if err != nil || len(facts.RoleAssignments) != 1 || len(facts.ProfileBindings) != 1 {
		t.Fatalf("facts=%#v error=%v", facts, err)
	}
	if facts.RoleAssignments[0].BindingKey != "binding" || facts.RoleAssignments[0].ExpiresAt != nil || facts.ProfileBindings[0].IdentityUserID != "user" {
		t.Fatalf("facts=%#v", facts)
	}
	closeDB()
}

func TestIdentityUserProjectionFactsBatchesByParameterBudget(t *testing.T) {
	state := &identitySQLState{}
	store, closeDB := scriptedSQLIdentity(state)
	defer closeDB()
	userIDs := make([]string, identityProjectionBatchMaxItems+1)
	for index := range userIDs {
		userIDs[index] = fmt.Sprintf("user-%04d", index)
	}
	if _, err := store.ListIdentityUserProjectionFacts(t.Context(), "workspace", userIDs); err != nil {
		t.Fatal(err)
	}
	if state.queryCount != 4 {
		t.Fatalf("query count=%d, want 4 for two batches across two fact owners", state.queryCount)
	}
}
