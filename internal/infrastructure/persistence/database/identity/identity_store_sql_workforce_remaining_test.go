package identity

import (
	"database/sql/driver"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func workforceProfileRow() []driver.Value {
	return []driver.Value{
		"profile", "organization", "user", "E-1", "employee", "active",
		nil, nil, nil, int64(1),
	}
}

func workforceAssignmentRow() []driver.Value {
	return []driver.Value{
		"assignment", "profile", "unit", nil, nil, "primary",
		nil, nil, "active", int64(1),
	}
}

func TestIdentityWorkforceProfileSQLRemainingFailures(t *testing.T) {
	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{
			columns: []string{"only"},
			rows:    [][]driver.Value{{"value"}},
		}}},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		if _, err := store.ListIdentityWorkforceProfiles(t.Context(), "workspace"); err == nil {
			t.Fatal("profile list failure ignored")
		}
		closeDB()
	}

	valid := identitymodel.IdentityWorkforceProfile{
		ID: "profile", OrganizationID: "organization", IdentityUserID: "user",
		WorkerNo: "E-1", WorkerType: identitymodel.IdentityWorkerEmployee,
		WorkStatus: identitymodel.IdentityWorkActive,
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "workspace", identitymodel.IdentityWorkforceProfile{}); err == nil {
		t.Fatal("empty profile ID accepted")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{beginErr: errProfileBindingSQL})
	if err := store.UpsertIdentityWorkforceProfile(t.Context(), "workspace", valid); !errors.Is(err, errProfileBindingSQL) {
		t.Fatalf("profile begin error=%v", err)
	}
	closeDB()

	for name, test := range map[string]struct {
		workspace string
		profile   identitymodel.IdentityWorkforceProfile
		state     *identitySQLState
	}{
		"workspace": {workspace: "", profile: valid, state: &identitySQLState{}},
		"id":        {workspace: "workspace", state: &identitySQLState{}},
		"upsert":    {workspace: "workspace", profile: valid, state: &identitySQLState{execFailAt: 1, failure: errProfileBindingSQL}},
	} {
		t.Run(name, func(t *testing.T) {
			store, closeDB := scriptedSQLIdentity(test.state)
			defer closeDB()
			if err := store.writeIdentityWorkforceProfile(t.Context(), store.db, test.workspace, test.profile); err == nil {
				t.Fatal("profile write failure ignored")
			}
		})
	}

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"},
		rows:    [][]driver.Value{workforceProfileRow()},
	}}})
	profiles, err := store.ListIdentityWorkforceProfiles(t.Context(), "workspace")
	if err != nil || len(profiles) != 1 || profiles[0].ID != "profile" {
		t.Fatalf("profiles=%#v error=%v", profiles, err)
	}
	closeDB()
}

func TestIdentityWorkforceAssignmentSQLRemainingFailures(t *testing.T) {
	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{querySteps: []identitySQLQueryStep{{
			columns: []string{"only"},
			rows:    [][]driver.Value{{"value"}},
		}}},
	} {
		store, closeDB := scriptedSQLIdentity(state)
		if _, err := store.ListIdentityWorkforceAssignments(t.Context(), "workspace", "profile"); err == nil {
			t.Fatal("assignment list failure ignored")
		}
		closeDB()
	}

	valid := identitymodel.IdentityWorkforceAssignment{
		ID: "assignment", WorkforceProfileID: "profile", OrganizationUnitID: "unit",
		AssignmentType: identitymodel.IdentityWorkforceAssignmentPrimary,
		Status:         identitymodel.IdentityStatusActive,
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.UpsertIdentityWorkforceAssignment(t.Context(), "workspace", identitymodel.IdentityWorkforceAssignment{}); err == nil {
		t.Fatal("empty assignment ID accepted")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{beginErr: errProfileBindingSQL})
	if err := store.UpsertIdentityWorkforceAssignment(t.Context(), "workspace", valid); !errors.Is(err, errProfileBindingSQL) {
		t.Fatalf("assignment begin error=%v", err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{execFailAt: 1, failure: errProfileBindingSQL})
	if err := store.UpsertIdentityWorkforceAssignment(t.Context(), "workspace", valid); !errors.Is(err, errProfileBindingSQL) {
		t.Fatalf("assignment write error=%v", err)
	}
	closeDB()

	for name, test := range map[string]struct {
		workspace  string
		assignment identitymodel.IdentityWorkforceAssignment
		state      *identitySQLState
	}{
		"workspace": {workspace: "", assignment: valid, state: &identitySQLState{}},
		"id":        {workspace: "workspace", state: &identitySQLState{}},
		"upsert":    {workspace: "workspace", assignment: valid, state: &identitySQLState{execFailAt: 1, failure: errProfileBindingSQL}},
	} {
		t.Run(name, func(t *testing.T) {
			store, closeDB := scriptedSQLIdentity(test.state)
			defer closeDB()
			if err := store.writeIdentityWorkforceAssignment(t.Context(), store.db, test.workspace, test.assignment); err == nil {
				t.Fatal("assignment write failure ignored")
			}
		})
	}

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version"},
		rows:    [][]driver.Value{workforceAssignmentRow()},
	}}})
	assignments, err := store.ListIdentityWorkforceAssignments(t.Context(), "workspace", "")
	if err != nil || len(assignments) != 1 || assignments[0].ID != "assignment" {
		t.Fatalf("assignments=%#v error=%v", assignments, err)
	}
	closeDB()
}
