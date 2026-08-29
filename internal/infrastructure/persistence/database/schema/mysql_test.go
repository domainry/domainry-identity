package schema_test

import (
	"path/filepath"
	"testing"

	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestMySQLTextDefaultsUseExpressions(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "schema.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetEngineForTesting("mysql"); err != nil {
		t.Fatal(err)
	}
	for input, want := range map[string]string{
		"TEXT NOT NULL DEFAULT ''":   "TEXT NOT NULL DEFAULT ('')",
		"TEXT NOT NULL DEFAULT '[]'": "TEXT NOT NULL DEFAULT ('[]')",
		"TEXT NOT NULL DEFAULT '{}'": "TEXT NOT NULL DEFAULT ('{}')",
		"TEXT NOT NULL":              "TEXT NOT NULL",
	} {
		if got := store.ColumnDefinition(input); got != want {
			t.Fatalf("columnDefinition(%q) = %q, want %q", input, got, want)
		}
	}
}
