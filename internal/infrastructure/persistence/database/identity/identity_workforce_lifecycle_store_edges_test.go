package identity

import (
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityWorkforceLifecycleValidationTransactionAndCommitFailures(t *testing.T) {
	wantErr := errors.New("workforce lifecycle storage failed")
	for _, test := range []struct {
		name     string
		state    identitySQLState
		mutation identitymodel.IdentityWorkforceLifecycleMutation
	}{
		{
			name:     "invalid workspace",
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{},
		},
		{
			name:     "begin",
			state:    identitySQLState{beginErr: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{WorkspaceID: "default"},
		},
		{
			name:  "profile write",
			state: identitySQLState{execFailAt: 1, failure: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{
				WorkspaceID: "default",
				Profile:     &identitymodel.IdentityWorkforceProfile{ID: "profile-1"},
			},
		},
		{
			name:  "end assignment update",
			state: identitySQLState{execFailAt: 1, failure: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{
				WorkspaceID:    "default",
				EndAssignments: []identitymodel.IdentityWorkforceAssignmentEnd{{AssignmentID: "assignment-1"}},
			},
		},
		{
			name:  "end assignment rows affected",
			state: identitySQLState{rowsFailAt: 1, failure: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{
				WorkspaceID:    "default",
				EndAssignments: []identitymodel.IdentityWorkforceAssignmentEnd{{AssignmentID: "assignment-1"}},
			},
		},
		{
			name:  "upsert assignment",
			state: identitySQLState{execFailAt: 1, failure: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{
				WorkspaceID:       "default",
				UpsertAssignments: []identitymodel.IdentityWorkforceAssignment{{ID: "assignment-1"}},
			},
		},
		{
			name:  "revoke entitlements update",
			state: identitySQLState{execFailAt: 1, failure: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{
				WorkspaceID: "default", RevokeEntitlements: true,
			},
		},
		{
			name:  "revoke entitlements rows affected",
			state: identitySQLState{rowsFailAt: 1, failure: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{
				WorkspaceID: "default", RevokeEntitlements: true, ActorID: "operator",
			},
		},
		{
			name:     "commit",
			state:    identitySQLState{commitErr: wantErr},
			mutation: identitymodel.IdentityWorkforceLifecycleMutation{WorkspaceID: "default"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, closeDB := scriptedSQLIdentity(&test.state)
			defer closeDB()
			if _, err := store.ApplyIdentityWorkforceLifecycle(t.Context(), test.mutation); err == nil {
				t.Fatal("expected lifecycle failure")
			}
		})
	}
}

func TestIdentityWorkforceLifecycleCountsAndFallbackActorWithoutProfile(t *testing.T) {
	state := &identitySQLState{}
	store, closeDB := scriptedSQLIdentity(state)
	defer closeDB()
	result, err := store.ApplyIdentityWorkforceLifecycle(t.Context(), identitymodel.IdentityWorkforceLifecycleMutation{
		WorkspaceID:        "default",
		EndAssignments:     []identitymodel.IdentityWorkforceAssignmentEnd{{AssignmentID: "assignment-1", EffectiveTo: "2026-07-27"}},
		RevokeEntitlements: true,
		Reason:             " ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != nil || result.EndedAssignmentCount != 1 || result.RevokedEntitlementCount != 1 || state.execCount != 2 {
		t.Fatalf("result=%+v execs=%d", result, state.execCount)
	}
}
