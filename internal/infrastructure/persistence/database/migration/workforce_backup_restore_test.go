package migration_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	migrationcontract "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSQLiteBackupRestorePreservesAccountAndWorkforceGraph(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "runtime.db")
	backupDirectory := filepath.Join(directory, "backups")
	cfg := config.Config{
		DatabaseDriver:     "sqlite",
		DBPath:             databasePath,
		MigrationBackupDir: backupDirectory,
	}
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO _identity_users (id, workspace_id, name, email, phone, status, created_at, updated_at)
		 VALUES ('user-1', 'workspace-a', 'Account One', 'one@example.com', '', 'active', '2026-07-25T00:00:00Z', '2026-07-25T00:00:00Z')`,
		`INSERT INTO _identity_workforce_profiles
		 (id, workspace_id, organization_id, identity_user_id, worker_no, worker_type, work_status, start_date, version, created_at, updated_at)
		 VALUES ('workforce-1', 'workspace-a', 'organization-1', 'user-1', 'E-001', 'employee', 'active', '2026-01-01', 1, '2026-07-25T00:00:00Z', '2026-07-25T00:00:00Z')`,
		`INSERT INTO _identity_workforce_assignments
		 (id, workspace_id, workforce_profile_id, organization_unit_id, manager_workforce_profile_id, assignment_type, effective_from, status, version, created_at, updated_at)
		 VALUES ('assignment-1', 'workspace-a', 'workforce-1', 'department-1', 'manager-1', 'primary', '2026-01-01', 'active', 1, '2026-07-25T00:00:00Z', '2026-07-25T00:00:00Z')`,
		`INSERT INTO _identity_workforce_migration_receipts
		 (id, workspace_id, identity_user_id, workforce_profile_id, workforce_assignment_id, legacy_facts_json, migrated_at)
		 VALUES ('receipt-1', 'workspace-a', 'user-1', 'workforce-1', 'assignment-1', '{"employee_number":"E-001"}', '2026-07-25T00:00:00Z')`,
	} {
		if _, err := store.DB().ExecContext(t.Context(), statement); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
	}
	backupPath, err := store.CreateSQLiteMigrationBackup(t.Context(), cfg)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	key := store.SecretMaterialKey()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restoredPath := filepath.Join(directory, "restored.db")
	if err := migrationcontract.DecryptBackupFile(backupPath, restoredPath, key[:]); err != nil {
		t.Fatal(err)
	}
	restored, err := sql.Open("sqlite", restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })

	var accountName, workerNumber, organizationUnitID, managerProfileID, legacyFacts string
	if err := restored.QueryRowContext(t.Context(), `SELECT name FROM _identity_users WHERE workspace_id = 'workspace-a' AND id = 'user-1'`).Scan(&accountName); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRowContext(t.Context(), `SELECT worker_no FROM _identity_workforce_profiles WHERE workspace_id = 'workspace-a' AND id = 'workforce-1'`).Scan(&workerNumber); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRowContext(t.Context(), `SELECT organization_unit_id, manager_workforce_profile_id FROM _identity_workforce_assignments WHERE workspace_id = 'workspace-a' AND id = 'assignment-1'`).Scan(&organizationUnitID, &managerProfileID); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRowContext(t.Context(), `SELECT legacy_facts_json FROM _identity_workforce_migration_receipts WHERE workspace_id = 'workspace-a' AND id = 'receipt-1'`).Scan(&legacyFacts); err != nil {
		t.Fatal(err)
	}
	if accountName != "Account One" || workerNumber != "E-001" || organizationUnitID != "department-1" || managerProfileID != "manager-1" || legacyFacts != `{"employee_number":"E-001"}` {
		t.Fatalf("restored identity graph drifted: account=%q worker=%q unit=%q manager=%q legacy=%q", accountName, workerNumber, organizationUnitID, managerProfileID, legacyFacts)
	}
}
