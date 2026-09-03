package schema

import (
	"strings"
	"testing"

	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func TestIdentityPermissionsSchemaRendersThroughDomainryORM(t *testing.T) {
	for _, name := range []ormdialect.Name{ormdialect.SQLite, ormdialect.MySQL, ormdialect.Postgres} {
		t.Run(string(name), func(t *testing.T) {
			dialect, err := ormdialect.New(name)
			if err != nil {
				t.Fatal(err)
			}
			renderer := dialect.WithSchema("identity")
			statement, arguments, err := identityPermissionsTableDefinition(renderer).Build()
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"_identity_permissions", "permission_key", "source_owner", "definition_status", "source_snapshot_hash", "UNIQUE", "workspace_id"} {
				if !strings.Contains(statement, required) {
					t.Fatalf("statement %q is missing %q", statement, required)
				}
			}
			if len(arguments) != 0 {
				t.Fatalf("DDL arguments=%v", arguments)
			}
			for _, index := range identityPermissionIndexSpecs {
				statement, arguments, err := identityPermissionIndexDefinition(renderer, index).Build()
				if err != nil {
					t.Fatal(err)
				}
				for _, required := range append([]string{identityPermissionsTable, index.name}, index.columns...) {
					if !strings.Contains(statement, required) {
						t.Fatalf("index statement %q is missing %q", statement, required)
					}
				}
				if len(arguments) != 0 {
					t.Fatalf("index DDL arguments=%v", arguments)
				}
			}
		})
	}
}
