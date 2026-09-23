package schema

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
	ormschema "github.com/domainry/domainry-orm/schema"
	_ "modernc.org/sqlite"
)

type organizationUnitMigrationStore struct{ scriptedSchemaStore }

func (s organizationUnitMigrationStore) CreateIndexIfMissing(ctx context.Context, table, index string, unique bool, columns ...string) error {
	return s.engineProfile().CreateIndexIfMissing(ctx, s.db, s.renderer(), s.DatabaseSchema(), "", table, index, unique, columns...)
}

func TestOrganizationUnitDeliveryV10UpgradeBackfillsSiblingIdentity(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "identity-v9.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := organizationUnitMigrationStore{scriptedSchemaStore{db: database, driver: "sqlite"}}

	statement, arguments, err := ormschema.NewTable(store.SchemaRenderer(), "_identity_organization_units").
		Columns(
			ormschema.Column("id", ormschema.TextKey(191)).NotNull(),
			ormschema.Column("workspace_id", ormschema.TextKey(191)).NotNull(),
			ormschema.Column("code", ormschema.TextKey(191)).NotNull(),
			ormschema.Column("name", ormschema.Text()).NotNull(),
			ormschema.Column("node_type", ormschema.TextKey(191)).NotNull(),
			ormschema.Column("parent_id", ormschema.TextKey(191)),
			ormschema.Column("path", ormschema.Text()).NotNull(),
			ormschema.Column("ancestor_ids", ormschema.Text()).NotNull(),
			ormschema.Column("depth", ormschema.Integer()).NotNull(),
			ormschema.Column("sort_order", ormschema.Integer()).NotNull().DefaultValue(0),
			ormschema.Column("status", ormschema.TextKey(191)).NotNull().DefaultValue("active"),
			ormschema.Column("created_at", ormschema.TextKey(191)).NotNull(),
			ormschema.Column("updated_at", ormschema.TextKey(191)).NotNull(),
		).
		PrimaryKey("id").Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
	parentID := "company-a"
	for _, item := range []identitymodel.IdentityOrganizationUnit{
		{ID: parentID, Code: "COMPANY-A", Name: "Company A", NodeType: identitymodel.IdentityOrganizationUnitCompany, Path: "/company-a", AncestorIDs: []string{}, Status: identitymodel.IdentityStatusActive},
		{ID: "department-sales", Code: "SALES", Name: "Sales", NodeType: identitymodel.IdentityOrganizationUnitDepartment, ParentID: &parentID, Path: "/company-a/department-sales", AncestorIDs: []string{parentID}, Depth: 1, Status: identitymodel.IdentityStatusActive},
	} {
		var persistedParentID any
		if item.ParentID != nil {
			persistedParentID = *item.ParentID
		}
		insert, values, buildErr := query.NewWorkspaceInsertBuilder(store.SchemaRenderer(), "_identity_organization_units", "workspace-primary").
			Columns("id", "code", "name", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at").
			Values(item.ID, item.Code, item.Name, string(item.NodeType), persistedParentID, item.Path, "[]", item.Depth, item.SortOrder, string(item.Status), "v9", "v9").Build()
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		if _, execErr := database.ExecContext(t.Context(), insert, values...); execErr != nil {
			t.Fatal(execErr)
		}
	}

	if err := EnsureIdentitySchema(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	columns, err := store.TableColumns(t.Context(), "_identity_organization_units")
	if err != nil || !columns["sibling_key"] {
		t.Fatalf("v10 sibling key column=%v err=%v", columns["sibling_key"], err)
	}
	indexes, err := store.TableIndexes(t.Context(), "_identity_organization_units")
	if err != nil || !indexes["uniq_identity_organization_unit_sibling_name"] {
		t.Fatalf("v10 sibling unique index=%v err=%v indexes=%v", indexes["uniq_identity_organization_unit_sibling_name"], err, indexes)
	}
	for _, item := range []struct {
		id       string
		parentID *string
		name     string
	}{
		{id: parentID, name: "Company A"},
		{id: "department-sales", parentID: &parentID, name: "Sales"},
	} {
		var key string
		lookup, values, buildErr := query.NewWorkspaceSelectBuilder(store.SchemaRenderer(), "_identity_organization_units", "workspace-primary").
			Columns("sibling_key").Where(query.Equal("id", item.id)).Build()
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		if queryErr := database.QueryRowContext(t.Context(), lookup, values...).Scan(&key); queryErr != nil {
			t.Fatal(queryErr)
		}
		if expected := identitymodel.IdentityOrganizationUnitSiblingKey(item.parentID, item.name); key != expected {
			t.Fatalf("%s sibling key=%q want=%q", item.id, key, expected)
		}
	}
	for _, table := range []string{"_identity_organization_unit_delivery_states", "_identity_organization_unit_deliveries", "_identity_store_organization_states", "_identity_store_organization_deliveries"} {
		if exists, existsErr := store.SchemaTableExists(t.Context(), table); existsErr != nil || exists {
			t.Fatalf("retired table %s exists=%v err=%v", table, exists, existsErr)
		}
	}
	if err := EnsureIdentitySchema(t.Context(), store); err != nil {
		t.Fatalf("idempotent v10 upgrade: %v", err)
	}
}
