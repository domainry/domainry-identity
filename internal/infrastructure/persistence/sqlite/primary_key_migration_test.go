package sqlite

import (
	"database/sql"
	"reflect"
	"testing"

	persistencedriver "github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func TestEnsureCompositePrimaryKeyMigratesWorkspaceCredentialIdentity(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TABLE identity_auth_provider_credentials (
		workspace_id TEXT NOT NULL,
		provider_key TEXT PRIMARY KEY,
		configuration_json TEXT NOT NULL,
		secret_envelope TEXT NOT NULL,
		updated_by TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO identity_auth_provider_credentials VALUES (?, ?, '{}', 'secret', 'user', 'created', 'updated')`, "workspace-a", "oidc"); err != nil {
		t.Fatal(err)
	}
	dialect, _ := ormdialect.New(ormdialect.SQLite)
	renderer, err := dialect.WithNamespace("", "identity_")
	if err != nil {
		t.Fatal(err)
	}
	if err := persistencedriver.ProfileFor(Dialect{}).EnsureCompositePrimaryKey(t.Context(), database, renderer, "", "identity_", "auth_provider_credentials", "workspace_id", "provider_key"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO identity_auth_provider_credentials VALUES (?, ?, '{}', 'secret', 'user', 'created', 'updated')`, "workspace-b", "oidc"); err != nil {
		t.Fatalf("same provider must coexist across workspaces: %v", err)
	}
	rows, err := database.Query(`PRAGMA table_info("identity_auth_provider_credentials")`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	primary := map[int]string{}
	for rows.Next() {
		var position, notNull, primaryOrder int
		var name, typeName string
		var defaultValue sql.NullString
		if err := rows.Scan(&position, &name, &typeName, &notNull, &defaultValue, &primaryOrder); err != nil {
			t.Fatal(err)
		}
		if primaryOrder > 0 {
			primary[primaryOrder] = name
		}
	}
	if got := []string{primary[1], primary[2]}; !reflect.DeepEqual(got, []string{"workspace_id", "provider_key"}) {
		t.Fatalf("primary key=%v", got)
	}
}
