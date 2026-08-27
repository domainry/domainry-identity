package identity

import (
	"database/sql/driver"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestMemoryWorkforceFinalConditions(t *testing.T) {
	store := NewMemoryIdentityStore()
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", identitymodel.IdentityWorkforceProfile{}); err == nil {
		t.Fatal("empty profile accepted")
	}
	profile := identitymodel.IdentityWorkforceProfile{ID: "b", OrganizationID: "org", IdentityUserID: "user-b", WorkerNo: "B", Version: 2}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", profile); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", profile); err != nil {
		t.Fatalf("same profile update failed: %v", err)
	}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "other", identitymodel.IdentityWorkforceProfile{ID: "foreign", OrganizationID: "org", IdentityUserID: "foreign", WorkerNo: "foreign"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", identitymodel.IdentityWorkforceProfile{ID: "other-org", OrganizationID: "other", IdentityUserID: "other", WorkerNo: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", identitymodel.IdentityWorkforceProfile{ID: "identity-conflict", OrganizationID: "org", IdentityUserID: "user-b", WorkerNo: "unique"}); err == nil {
		t.Fatal("identity conflict accepted")
	}
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "default", identitymodel.IdentityWorkforceProfile{ID: "worker-conflict", OrganizationID: "org", IdentityUserID: "unique", WorkerNo: "B"}); err == nil {
		t.Fatal("worker number conflict accepted")
	}

	if err := store.UpsertIdentityWorkforceAssignment(t.Context(), "default", identitymodel.IdentityWorkforceAssignment{}); err == nil {
		t.Fatal("empty assignment accepted")
	}
	for _, assignment := range []identitymodel.IdentityWorkforceAssignment{
		{ID: "b", WorkforceProfileID: "b", Version: 2},
		{ID: "a", WorkforceProfileID: "a"},
	} {
		if err := store.UpsertIdentityWorkforceAssignment(t.Context(), "default", assignment); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.UpsertIdentityWorkforceAssignment(t.Context(), "other", identitymodel.IdentityWorkforceAssignment{ID: "foreign", WorkforceProfileID: "b"}); err != nil {
		t.Fatal(err)
	}
	all, err := store.ListIdentityWorkforceAssignments(t.Context(), "default", "")
	if err != nil || len(all) != 2 || all[0].ID != "a" || all[1].ID != "b" {
		t.Fatalf("all assignments=%#v error=%v", all, err)
	}
	filtered, err := store.ListIdentityWorkforceAssignments(t.Context(), "default", "b")
	if err != nil || len(filtered) != 1 || filtered[0].ID != "b" {
		t.Fatalf("filtered assignments=%#v error=%v", filtered, err)
	}
}

func TestSQLIdentityBootstrapFinalFailureStages(t *testing.T) {
	wantErr := errors.New("bootstrap stage")
	for _, call := range []func(*SQLIdentityStore) error{
		func(store *SQLIdentityStore) error {
			return store.ApplyIdentityBootstrapAtomically(t.Context(), "default", nil, nil, []identitymodel.IdentityWorkforceProfile{{ID: "profile"}}, nil, nil)
		},
		func(store *SQLIdentityStore) error {
			return store.ApplyIdentityBootstrapAtomically(t.Context(), "default", nil, nil, nil, []identitymodel.IdentityWorkforceAssignment{{ID: "assignment"}}, nil)
		},
	} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{execFailAt: 1, failure: wantErr})
		if err := call(store); !errors.Is(err, wantErr) {
			t.Fatalf("bootstrap error=%v", err)
		}
		closeDB()
	}
}

func TestSQLIdentityWorkforceOnboardingFinalFailureStages(t *testing.T) {
	base := memoryOnboardingMutation()
	cases := []struct {
		state  identitySQLState
		mutate func(*identitymodel.IdentityWorkforceOnboardingMutation)
	}{
		{mutate: func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.WorkspaceID = " " }},
		{state: identitySQLState{beginErr: errors.New("begin")}},
		{mutate: func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.User.ID = "" }},
		{mutate: func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.Profile.ID = "" }},
		{mutate: func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.Assignment.ID = "" }},
		{mutate: func(value *identitymodel.IdentityWorkforceOnboardingMutation) { value.RoleAssignments[0].RoleID = "" }},
		{state: identitySQLState{commitErr: errors.New("commit")}},
	}
	for index := range cases {
		mutation := base
		mutation.RoleAssignments = append([]identitymodel.IdentityUserRoleAssignment(nil), base.RoleAssignments...)
		if cases[index].mutate != nil {
			cases[index].mutate(&mutation)
		}
		store, closeDB := scriptedSQLIdentity(&cases[index].state)
		if _, err := store.ApplyIdentityWorkforceOnboarding(t.Context(), mutation); err == nil {
			t.Fatalf("onboarding failure case %d ignored", index)
		}
		closeDB()
	}
}

func TestIdentitySubjectExportFinalFailureStages(t *testing.T) {
	wantErr := errors.New("subject export stage")
	userColumns := make([]string, 18)
	userRow := make([]driver.Value, 18)
	for index := range userColumns {
		userColumns[index], userRow[index] = "c", "v"
	}
	userRow[15] = int64(1)
	countStep := func() identitySQLQueryStep {
		return identitySQLQueryStep{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}}
	}

	previewFailure := &identitySQLState{
		queryFailAt: 2,
		failure:     wantErr,
		querySteps:  []identitySQLQueryStep{{columns: userColumns, rows: [][]driver.Value{userRow}}},
	}
	store, closeDB := scriptedSQLIdentity(previewFailure)
	if _, err := NewIdentitySubjectLifecycleStore(store).ExportSubject(t.Context(), "default", "user"); !errors.Is(err, wantErr) {
		t.Fatalf("preview error=%v", err)
	}
	closeDB()

	steps := []identitySQLQueryStep{{columns: userColumns, rows: [][]driver.Value{userRow}}}
	for range 6 {
		steps = append(steps, countStep())
	}
	relationshipFailure := &identitySQLState{queryFailAt: 8, failure: wantErr, querySteps: steps}
	store, closeDB = scriptedSQLIdentity(relationshipFailure)
	if _, err := NewIdentitySubjectLifecycleStore(store).ExportSubject(t.Context(), "default", "user"); !errors.Is(err, wantErr) {
		t.Fatalf("relationship error=%v", err)
	}
	closeDB()
}

func TestIdentitySubjectRelationshipExportFinalFailures(t *testing.T) {
	wantErr := errors.New("relationship stage")
	states := []*identitySQLState{
		{queryFailAt: 1, failure: wantErr},
		{querySteps: []identitySQLQueryStep{{columns: []string{"id"}, rows: [][]driver.Value{{"only-one"}}}}},
		{querySteps: []identitySQLQueryStep{{columns: make([]string, 8), nextErr: wantErr}}},
	}
	for index, state := range states {
		store, closeDB := scriptedSQLIdentity(state)
		lifecycle := NewIdentitySubjectLifecycleStore(store)
		if _, err := lifecycle.exportSubjectRelationships(t.Context(), "default", "user"); err == nil {
			t.Fatalf("relationship failure case %d ignored", index)
		}
		closeDB()
	}
}
