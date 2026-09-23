package schema

import (
	"testing"
)

func TestMetadataSchemaOwnsNoPrivateTables(t *testing.T) {
	state := &schemaSQLState{}
	database := openSchemaScriptedDB(state)
	t.Cleanup(func() { _ = database.Close() })

	if err := EnsureMetadataSchema(t.Context(), scriptedSchemaStore{db: database, driver: "mysql"}); err != nil {
		t.Fatal(err)
	}

	if len(state.execQueries) != 0 {
		t.Fatalf("Identity metadata schema retained private mutations: %v", state.execQueries)
	}
}
