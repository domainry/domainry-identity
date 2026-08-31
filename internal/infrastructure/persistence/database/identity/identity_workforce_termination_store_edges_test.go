package identity

import (
	"database/sql/driver"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func workforceTerminationMutation() identitymodel.IdentityWorkforceTerminationMutation {
	return identitymodel.IdentityWorkforceTerminationMutation{
		WorkspaceID: "workspace-primary",
		Profile: identitymodel.IdentityWorkforceProfile{
			ID: "profile", IdentityUserID: "worker", WorkStatus: identitymodel.IdentityWorkTerminated,
		},
		EffectiveAt: "2026-07-26",
	}
}

func TestWorkforceTerminationValidationAndTransactionFailures(t *testing.T) {
	mutation := workforceTerminationMutation()
	for _, invalid := range []identitymodel.IdentityWorkforceTerminationMutation{
		{},
		{WorkspaceID: "workspace-primary", Profile: identitymodel.IdentityWorkforceProfile{IdentityUserID: "worker"}},
		{WorkspaceID: "workspace-primary", Profile: identitymodel.IdentityWorkforceProfile{ID: "profile"}},
	} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{})
		_, err := store.TerminateIdentityWorkforce(t.Context(), invalid)
		closeDB()
		if err == nil {
			t.Fatalf("invalid mutation accepted: %+v", invalid)
		}
	}
	wantErr := errors.New("termination storage failed")
	cases := []identitySQLState{
		{beginErr: wantErr},
		{execFailAt: 1, failure: wantErr},
		{execFailAt: 3, failure: wantErr},
		{rowsFailAt: 3, failure: wantErr},
		{execFailAt: 4, failure: wantErr},
		{rowsFailAt: 4, failure: wantErr},
		{queryFailAt: 1, failure: wantErr},
		{
			querySteps: []identitySQLQueryStep{
				{columns: []string{"count"}, rows: [][]driver.Value{{0}}},
			},
			commitErr: wantErr,
		},
	}
	for index := range cases {
		store, closeDB := scriptedSQLIdentity(&cases[index])
		_, err := store.TerminateIdentityWorkforce(t.Context(), mutation)
		closeDB()
		if err == nil {
			t.Fatalf("failure case %d succeeded", index)
		}
	}
}

func TestWorkforceTerminationDefaultsAndQueryHelpers(t *testing.T) {
	mutation := workforceTerminationMutation()
	state := &identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: []string{"count"}, rows: [][]driver.Value{{2}}},
	}}
	store, closeDB := scriptedSQLIdentity(state)
	result, err := store.TerminateIdentityWorkforce(t.Context(), mutation)
	closeDB()
	if err != nil || result.Profile.Version != 0 || result.PreservedProfileBindings != 2 ||
		result.EndedAssignmentCount != 1 || result.RevokedEntitlementCount != 1 {
		t.Fatalf("result=%+v error=%v", result, err)
	}

	if valueOrFallback("value", "fallback") != "value" || valueOrFallback("", "fallback") != "fallback" {
		t.Fatal("fallback helper changed")
	}
}
