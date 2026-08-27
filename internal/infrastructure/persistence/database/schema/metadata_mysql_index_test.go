package schema

import (
	"strings"
	"testing"
)

func TestMetadataSchemaExcludesPlaneNotificationTables(t *testing.T) {
	state := &schemaSQLState{}
	database := openSchemaScriptedDB(state)
	t.Cleanup(func() { _ = database.Close() })

	if err := EnsureMetadataSchema(t.Context(), scriptedSchemaStore{db: database, driver: "mysql"}); err != nil {
		t.Fatal(err)
	}

	for _, query := range state.execQueries {
		if strings.Contains(query, "notification_") {
			t.Fatalf("notification table leaked into Identity schema: %s", query)
		}
	}
	if !strings.Contains(strings.Join(state.execQueries, "\n"), "LONGTEXT") {
		t.Fatal("MySQL metadata documents were not mapped to LONGTEXT")
	}
}
