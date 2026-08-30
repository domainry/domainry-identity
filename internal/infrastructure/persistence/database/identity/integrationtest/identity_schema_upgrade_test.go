package identity_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityservice "github.com/domainry/domainry-identity/internal/domain/identity/service"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestEnsureIdentitySchemaAddsDepartmentSortOrderToExistingSQLiteDatabase(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity-upgrade.db"),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.DB().Exec(`CREATE TABLE _identity_departments (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    parent_id TEXT,
    path TEXT NOT NULL,
    ancestor_ids TEXT NOT NULL,
    depth INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`); err != nil {
		t.Fatalf("create legacy identity table: %v", err)
	}
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatalf("upgrade identity schema: %v", err)
	}
	if _, err := store.DB().Exec(`INSERT INTO _identity_departments
    (id, workspace_id, name, path, ancestor_ids, depth, sort_order, status, created_at, updated_at)
    VALUES ('sales', 'default', 'Sales', '/sales', '[]', 0, 20, 'active', 'now', 'now')`); err != nil {
		t.Fatalf("expected upgraded table to accept sort_order: %v", err)
	}
}

func TestEnsureIdentitySchemaMigratesLegacyUserWorkforceFactsAndDropsColumns(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-user-upgrade.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.DB().Exec(`CREATE TABLE _identity_users (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL,
    email TEXT NOT NULL, employee_no TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
    gender TEXT NOT NULL DEFAULT '', hire_date TEXT NOT NULL DEFAULT '', job_title TEXT NOT NULL DEFAULT '',
    job_level TEXT NOT NULL DEFAULT '', employment_type TEXT NOT NULL DEFAULT '',
    employment_status TEXT NOT NULL DEFAULT 'active', department_id TEXT, department_path TEXT,
    manager_id TEXT, manager_path TEXT NOT NULL DEFAULT '', manager_ancestor_ids TEXT NOT NULL DEFAULT '[]',
    manager_depth INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  )`); err != nil {
		t.Fatalf("create legacy identity users table: %v", err)
	}
	if _, err := store.DB().Exec(`CREATE INDEX idx_identity_users_department ON _identity_users(workspace_id, department_id);
CREATE INDEX idx_identity_users_manager ON _identity_users(workspace_id, manager_id);
CREATE INDEX idx_identity_users_manager_path ON _identity_users(workspace_id, manager_path);
INSERT INTO _identity_users
  (id, workspace_id, name, email, employee_no, phone, gender, hire_date, job_title, job_level, employment_type, employment_status, department_id, department_path, manager_id, manager_path, manager_ancestor_ids, manager_depth, status, created_at, updated_at)
VALUES
  ('manager', 'default', 'Manager', 'manager@example.com', 'M001', '', '', '2025-01-01', 'Director', 'L7', 'full_time', 'active', 'executive', '/executive', NULL, '', '[]', 0, 'active', 'now', 'now'),
  ('worker', 'default', 'Worker', 'worker@example.com', 'E001', '10000000001', 'other', '2026-01-01', 'Engineer', 'L4', 'contractor', 'on_leave', 'engineering', '/engineering', 'manager', '/manager/worker', '["manager"]', 1, 'active', 'now', 'now')`); err != nil {
		t.Fatalf("seed legacy identity users: %v", err)
	}
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatalf("upgrade identity schema: %v", err)
	}
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatalf("repeat identity schema upgrade: %v", err)
	}
	rows, err := store.DB().Query(`PRAGMA table_info(_identity_users)`)
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	_ = rows.Close()
	for _, removed := range []string{"employee_no", "gender", "hire_date", "job_title", "job_level", "employment_type", "employment_status", "department_id", "department_path", "manager_id", "manager_path", "manager_ancestor_ids", "manager_depth"} {
		if columns[removed] {
			t.Errorf("legacy _identity_users column %q still exists", removed)
		}
	}
	for _, retained := range []string{"id", "workspace_id", "name", "email", "phone", "status", "created_at", "updated_at"} {
		if !columns[retained] {
			t.Errorf("account column %q was removed", retained)
		}
	}
	var workerProfileID, workerNo, workerType, workStatus, startDate, primaryAssignmentID string
	if err := store.DB().QueryRow(`SELECT id, worker_no, worker_type, work_status, start_date, primary_assignment_id
FROM _identity_workforce_profiles WHERE workspace_id = 'default' AND identity_user_id = 'worker'`).
		Scan(&workerProfileID, &workerNo, &workerType, &workStatus, &startDate, &primaryAssignmentID); err != nil {
		t.Fatalf("read migrated worker profile: %v", err)
	}
	if workerNo != "E001" || workerType != "contractor" || workStatus != "suspended" || startDate != "2026-01-01" || primaryAssignmentID == "" {
		t.Fatalf("migrated worker profile=%q %q %q %q %q", workerNo, workerType, workStatus, startDate, primaryAssignmentID)
	}
	var unitID, managerProfileID, positionID, assignmentStatus string
	if err := store.DB().QueryRow(`SELECT organization_unit_id, manager_workforce_profile_id, position_id, status
FROM _identity_workforce_assignments WHERE workspace_id = 'default' AND id = ?`, primaryAssignmentID).
		Scan(&unitID, &managerProfileID, &positionID, &assignmentStatus); err != nil {
		t.Fatalf("read migrated worker assignment: %v", err)
	}
	var expectedManagerProfileID string
	if err := store.DB().QueryRow(`SELECT id FROM _identity_workforce_profiles WHERE workspace_id = 'default' AND identity_user_id = 'manager'`).Scan(&expectedManagerProfileID); err != nil {
		t.Fatal(err)
	}
	if unitID != "engineering" || managerProfileID != expectedManagerProfileID || !strings.HasPrefix(positionID, "legacy-position-") || assignmentStatus != "disabled" {
		t.Fatalf("migrated assignment unit=%q manager=%q position=%q status=%q", unitID, managerProfileID, positionID, assignmentStatus)
	}
	var receiptRaw string
	if err := store.DB().QueryRow(`SELECT legacy_facts_json FROM _identity_workforce_migration_receipts WHERE workspace_id = 'default' AND identity_user_id = 'worker'`).Scan(&receiptRaw); err != nil {
		t.Fatalf("read migration receipt: %v", err)
	}
	var receipt map[string]any
	if err := json.Unmarshal([]byte(receiptRaw), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["gender"] != "other" || receipt["job_level"] != "L4" || receipt["manager_path"] != "/manager/worker" {
		t.Fatalf("migration receipt lost legacy facts: %#v", receipt)
	}
	for table, want := range map[string]int{
		"_identity_workforce_profiles":           2,
		"_identity_workforce_assignments":        2,
		"_identity_workforce_migration_receipts": 2,
	} {
		var count int
		if err := store.DB().QueryRow("SELECT COUNT(*) FROM " + table + " WHERE workspace_id = 'default'").Scan(&count); err != nil || count != want {
			t.Fatalf("deterministic migration table=%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
	var legacyIndexCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_identity_users_department', 'idx_identity_users_manager', 'idx_identity_users_manager_path')`).Scan(&legacyIndexCount); err != nil || legacyIndexCount != 0 {
		t.Fatalf("legacy index count=%d err=%v", legacyIndexCount, err)
	}
}

func TestLegacyWorkforceBackfillPreservesDepartmentManagerAndSubordinateScope(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-scope-comparison.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().Exec(`CREATE TABLE _identity_users (
		id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL DEFAULT 'default', name TEXT NOT NULL,
		email TEXT NOT NULL, employee_no TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
		hire_date TEXT NOT NULL DEFAULT '', job_title TEXT NOT NULL DEFAULT '', job_level TEXT NOT NULL DEFAULT '',
		employment_type TEXT NOT NULL DEFAULT '', employment_status TEXT NOT NULL DEFAULT 'active',
		department_id TEXT, department_path TEXT, manager_id TEXT, manager_path TEXT NOT NULL DEFAULT '',
		manager_ancestor_ids TEXT NOT NULL DEFAULT '[]', manager_depth INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	);
	INSERT INTO _identity_users
		(id,workspace_id,name,email,employee_no,hire_date,employment_status,department_id,department_path,manager_id,manager_path,manager_ancestor_ids,manager_depth,status,created_at,updated_at)
	VALUES
		('manager','default','Manager','manager@example.test','M-1','2020-01-01','active','executive','/executive',NULL,'/manager','[]',0,'active','now','now'),
		('worker','default','Worker','worker@example.test','E-1','2021-01-01','active','engineering','/engineering','manager','/manager/worker','["manager"]',1,'active','now','now'),
		('nested','default','Nested','nested@example.test','E-2','2022-01-01','active','engineering','/engineering','worker','/manager/worker/nested','["manager","worker"]',2,'active','now','now')`); err != nil {
		t.Fatal(err)
	}
	legacy := map[string]struct {
		departmentID, departmentPath, reportingPath string
		reportingUsers                              []string
	}{
		"manager": {"executive", "/executive", "/manager", []string{"nested", "worker"}},
		"worker":  {"engineering", "/engineering", "/manager/worker", []string{"nested"}},
		"nested":  {"engineering", "/engineering", "/manager/worker/nested", []string{}},
	}
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	for _, department := range []identitymodel.IdentityDepartment{
		{ID: "executive", Name: "Executive", Path: "/executive", Status: identitymodel.IdentityStatusActive},
		{ID: "engineering", Name: "Engineering", Path: "/engineering", Status: identitymodel.IdentityStatusActive},
	} {
		if err := identity.UpsertIdentityDepartment(t.Context(), "default", department); err != nil {
			t.Fatal(err)
		}
	}
	domain := identityservice.NewIdentityDomainService(identity, nil)
	scoped, err := domain.ForWorkspace("default")
	if err != nil {
		t.Fatal(err)
	}
	for userID, expected := range legacy {
		principal, err := scoped.BuildPrincipal(t.Context(), userID)
		if err != nil {
			t.Fatalf("resolve %s: %v", userID, err)
		}
		if !principal.Known || principal.DepartmentID != expected.departmentID ||
			principal.DepartmentPath != expected.departmentPath ||
			principal.ReportingPath != expected.reportingPath ||
			!reflect.DeepEqual(principal.ReportingUserIDs, expected.reportingUsers) {
			t.Fatalf("scope mismatch user=%s principal=%+v expected=%+v", userID, principal, expected)
		}
	}
}
