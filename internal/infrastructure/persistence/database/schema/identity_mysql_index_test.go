package schema

import (
	"strings"
	"testing"
)

func TestIdentityProfileBindingMySQLIndexColumnsUseASCII(t *testing.T) {
	state := &schemaSQLState{}
	database := openSchemaScriptedDB(state)
	t.Cleanup(func() { _ = database.Close() })

	if err := EnsureIdentitySchema(t.Context(), scriptedSchemaStore{db: database, driver: "mysql"}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"_identity_profile_bindings", "_identity_profile_binding_receipts", "_identity_profile_binding_events"} {
		var ddl string
		for _, query := range state.execQueries {
			if strings.Contains(query, `"`+table+`"`) {
				ddl = query
				break
			}
		}
		if ddl == "" || !strings.Contains(ddl, "VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin") {
			t.Fatalf("table=%s DDL=%s", table, ddl)
		}
	}
}
