package identity

import (
	"database/sql/driver"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestCreatedRoleRequestDoesNotReturnIdentityBeforeCommit(t *testing.T) {
	failure := errors.New("created role request transaction failed")
	row := func(id int64) []identitySQLQueryStep {
		return []identitySQLQueryStep{{columns: []string{"id"}, rows: [][]driver.Value{{id}}}}
	}
	for _, test := range []struct {
		name  string
		state *identitySQLState
		cause error
	}{
		{"begin", &identitySQLState{beginErr: failure}, failure},
		{"insert", &identitySQLState{execFailAt: 1, failure: failure}, failure},
		{"read", &identitySQLState{queryFailAt: 1, failure: failure}, failure},
		{"missing-row", &identitySQLState{querySteps: []identitySQLQueryStep{{columns: []string{"id"}}}}, nil},
		{"invalid-row-id", &identitySQLState{querySteps: row(0)}, nil},
		{"commit", &identitySQLState{querySteps: row(17), commitErr: failure}, failure},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, closeDB := scriptedSQLIdentity(test.state)
			defer closeDB()
			created, err := store.CreateIdentityRoleRequest(t.Context(), "workspace-primary", identitymodel.IdentityRoleRequest{
				ID: 9999, RoleRequestID: "request-business", UserID: "user", RoleIDs: []string{"role"},
			})
			if err == nil || created.ID != 0 || created.RoleRequestID != "" {
				t.Fatalf("failed transaction leaked a created identity: id=%d request=%q err=%v", created.ID, created.RoleRequestID, err)
			}
			if test.cause != nil && !errors.Is(err, test.cause) {
				t.Fatalf("transaction cause was lost: %v", err)
			}
		})
	}
}
