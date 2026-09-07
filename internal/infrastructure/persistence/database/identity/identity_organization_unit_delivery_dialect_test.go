package identity

import (
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func TestOrganizationUnitDeliveryResolveRendersWorkspaceParentScopeForEveryDialect(t *testing.T) {
	tests := []struct {
		name        string
		renderer    ormdialect.Renderer
		placeholder string
		quotedTable string
	}{
		{name: "sqlite", renderer: sqlite.NewEngine().SQLDialect().WithSchema(""), placeholder: "?", quotedTable: `"_identity_organization_units"`},
		{name: "mysql", renderer: mysql.NewEngine().SQLDialect().WithSchema(""), placeholder: "?", quotedTable: "`_identity_organization_units`"},
		{name: "postgres", renderer: postgres.NewEngine().SQLDialect().WithSchema(""), placeholder: "$1", quotedTable: `"_identity_organization_units"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &identitySQLState{}
			store, cleanup := scriptedSQLIdentity(state)
			defer cleanup()
			store.renderer = test.renderer
			_, found, err := store.ResolveIdentityDeliveredOrganizationUnit(
				t.Context(), "workspace-primary", "department-sales", identitymodel.IdentityOrganizationUnitDepartment,
				identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"company-a"}},
			)
			if err != nil || found {
				t.Fatalf("found=%v err=%v", found, err)
			}
			if len(state.queryStatements) != 1 {
				t.Fatalf("queries=%v", state.queryStatements)
			}
			statement := state.queryStatements[0]
			for _, expected := range []string{test.quotedTable, "child", "parent", "workspace_id", "node_type", "status", test.placeholder} {
				if !strings.Contains(statement, expected) {
					t.Fatalf("%s resolve SQL omitted %q: %s", test.name, expected, statement)
				}
			}
		})
	}
}

func TestOrganizationUnitDeliveryParentLockRendersForEveryDialect(t *testing.T) {
	tests := []struct {
		name        string
		renderer    ormdialect.Renderer
		placeholder string
		quotedTable string
	}{
		{name: "sqlite", renderer: sqlite.NewEngine().SQLDialect().WithSchema(""), placeholder: "?", quotedTable: `"_identity_organization_units"`},
		{name: "mysql", renderer: mysql.NewEngine().SQLDialect().WithSchema(""), placeholder: "?", quotedTable: "`_identity_organization_units`"},
		{name: "postgres", renderer: postgres.NewEngine().SQLDialect().WithSchema(""), placeholder: "$1", quotedTable: `"_identity_organization_units"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement, arguments, err := buildIdentityOrganizationUnitParentLock(test.renderer, "workspace-primary", "company-a")
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{"UPDATE " + test.quotedTable, "updated_at", "workspace_id", test.placeholder} {
				if !strings.Contains(statement, expected) {
					t.Fatalf("%s parent lock SQL omitted %q: %s", test.name, expected, statement)
				}
			}
			if len(arguments) != 2 || arguments[0] != "workspace-primary" || arguments[1] != "company-a" {
				t.Fatalf("%s parent lock arguments=%#v", test.name, arguments)
			}
		})
	}
}
