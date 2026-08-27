package schema

import (
	"database/sql/driver"
	"testing"
)

func TestMigrateLegacyIdentityMenuAudiencePropagatesDropFailure(t *testing.T) {
	store, closeDB := schemaStoreForState(&schemaSQLState{
		querySteps: []schemaSQLQueryStep{{
			columns: []string{"cid", "name", "type", "notnull", "default", "pk"},
			rows:    [][]driver.Value{{int64(0), "audience", "TEXT", int64(0), nil, int64(0)}},
		}},
		execSteps: []schemaSQLExecStep{{err: errSchemaSQL}},
	})
	defer closeDB()
	if err := migrateLegacyIdentityMenuAudience(t.Context(), store); err == nil {
		t.Fatal("identity menu audience drop failure was ignored")
	}
}
