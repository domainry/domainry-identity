package schema

import (
	"strings"
	"testing"

	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func TestIdentityApplicationsSchemaRendersThroughDomainryORM(t *testing.T) {
	for _, name := range []ormdialect.Name{ormdialect.SQLite, ormdialect.MySQL, ormdialect.Postgres} {
		t.Run(string(name), func(t *testing.T) {
			dialect, err := ormdialect.New(name)
			if err != nil {
				t.Fatal(err)
			}
			statement, arguments, err := identityApplicationsTableDefinition(dialect.WithSchema("identity")).Build()
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"_identity_applications", "workspace_id", "application_key", "redirect_urls_json", "status", "UNIQUE"} {
				if !strings.Contains(statement, required) {
					t.Fatalf("statement %q is missing %q", statement, required)
				}
			}
			if len(arguments) != 0 {
				t.Fatalf("DDL arguments=%v", arguments)
			}
		})
	}
}
