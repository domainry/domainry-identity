package schema_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identityschema "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/schema"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

var errSchemaMutationFault = errors.New("schema mutation fault")

type schemaFaultStore struct {
	identityschema.Store
	failAt int
	step   int
}

type schemaDriverStore struct {
	identityschema.Store
	driver string
}

func (s schemaDriverStore) Driver() string { return s.driver }

func (s *schemaFaultStore) SchemaDB() identityschema.SQLDatabase {
	return schemaFaultDatabase{SQLDatabase: s.Store.SchemaDB(), owner: s}
}

func (s *schemaFaultStore) CreateIndexIfMissing(ctx context.Context, table, index string, unique bool, columns ...string) error {
	if s.fail() {
		return errSchemaMutationFault
	}
	return s.Store.CreateIndexIfMissing(ctx, table, index, unique, columns...)
}

func (s *schemaFaultStore) fail() bool {
	s.step++
	return s.step == s.failAt
}

type schemaFaultDatabase struct {
	identityschema.SQLDatabase
	owner *schemaFaultStore
}

func (d schemaFaultDatabase) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if d.owner.fail() {
		return nil, errSchemaMutationFault
	}
	return d.SQLDatabase.QueryContext(ctx, query, args...)
}

func (d schemaFaultDatabase) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if d.owner.fail() {
		return nil, errSchemaMutationFault
	}
	return d.SQLDatabase.ExecContext(ctx, query, args...)
}

func TestSchemaAssemblersPropagateEveryOrderedMutationFailure(t *testing.T) {
	tests := []struct {
		name   string
		ensure func(context.Context, identityschema.Store) error
	}{
		{name: "metadata", ensure: identityschema.EnsureMetadataSchema},
		{name: "identity", ensure: identityschema.EnsureIdentitySchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "schema.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })

			for failAt := 1; failAt < 512; failAt++ {
				faults := &schemaFaultStore{Store: store, failAt: failAt}
				err := test.ensure(t.Context(), faults)
				if faults.step < failAt {
					if err != nil {
						t.Fatalf("successful pass after %d mutations: %v", faults.step, err)
					}
					if faults.step == 0 {
						t.Fatal("schema assembler performed no mutations")
					}
					return
				}
				if !errors.Is(err, errSchemaMutationFault) {
					t.Fatalf("mutation %d was not propagated: step=%d err=%v", failAt, faults.step, err)
				}
			}
			t.Fatal("schema assembler exceeded mutation fault bound")
		})
	}
}

func TestSchemaAssemblersPreserveCancellation(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "schema-cancel.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ensure := range []func(context.Context, identityschema.Store) error{
		identityschema.EnsureMetadataSchema,
		identityschema.EnsureIdentitySchema,
	} {
		if err := ensure(cancelled, store); !errors.Is(err, context.Canceled) {
			t.Fatalf("schema cancellation=%v", err)
		}
	}
}

func TestSchemaAssemblersReachMySQLTypeBranchesBeforeMutation(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "schema-mysql-types.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for name, ensure := range map[string]func(context.Context, identityschema.Store) error{
		"metadata": identityschema.EnsureMetadataSchema,
		"identity": identityschema.EnsureIdentitySchema,
	} {
		t.Run(name, func(t *testing.T) {
			faults := &schemaFaultStore{Store: schemaDriverStore{Store: store, driver: "mysql"}, failAt: 1}
			if err := ensure(t.Context(), faults); !errors.Is(err, errSchemaMutationFault) {
				t.Fatalf("mysql first mutation error=%v", err)
			}
		})
	}
	postgresFaults := &schemaFaultStore{Store: schemaDriverStore{Store: store, driver: "postgres"}, failAt: 1}
	if err := identityschema.EnsureIdentitySchema(t.Context(), postgresFaults); !errors.Is(err, errSchemaMutationFault) {
		t.Fatalf("postgres identity first mutation error=%v", err)
	}
}

func TestCreateIndexIfMissingCoversDialectAndExistingIndexContracts(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "schema-index.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE index_fixture (id TEXT, scope TEXT)`); err != nil {
		t.Fatal(err)
	}
	faults := &schemaFaultStore{Store: store, failAt: 1}
	if err := faults.CreateIndexIfMissing(t.Context(), "index_fixture", "idx_fixture_fault", false, "id"); !errors.Is(err, errSchemaMutationFault) {
		t.Fatalf("index query fault=%v", err)
	}
	if err := store.CreateIndexIfMissing(t.Context(), "index_fixture", "idx_fixture_sqlite", false, "scope"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateIndexIfMissing(t.Context(), "index_fixture", "idx_fixture_sqlite", false, "scope"); err != nil {
		t.Fatalf("existing index was not idempotent: %v", err)
	}
	if err := store.CreateIndexIfMissing(t.Context(), "missing_table", "idx_missing", false, "id"); err == nil {
		t.Fatal("index creation failure was swallowed")
	}
}
