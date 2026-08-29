package schema

import (
	"database/sql"
	"database/sql/driver"
	"testing"
)

func schemaStoreForState(state *schemaSQLState, dialect ...string) (scriptedSchemaStore, func()) {
	db := openSchemaScriptedDB(state)
	store := scriptedSchemaStore{db: db}
	if len(dialect) > 0 {
		store.driver = dialect[0]
	}
	return store, func() { _ = db.Close() }
}

func TestIdentityWorkforceMigrationValueHelpers(t *testing.T) {
	if identityMigrationWorkerNo(legacyIdentityUserWorkforceFacts{UserID: "user", EmployeeNo: " E-1 "}) != "E-1" ||
		identityMigrationWorkerNo(legacyIdentityUserWorkforceFacts{UserID: "user"}) != "user" {
		t.Fatal("worker number normalization")
	}
	for input, want := range map[string]string{"contractor": "contractor", "temporary": "temporary", "employee": "employee"} {
		if got := identityMigrationWorkerType(input); got != want {
			t.Fatalf("worker type %q=%q", input, got)
		}
	}
	for input, want := range map[string]string{
		"terminated": "terminated", "on_leave": "suspended", "suspended": "suspended",
		"pending": "pending", "active": "active",
	} {
		if got := identityMigrationWorkStatus(input); got != want {
			t.Fatalf("work status %q=%q", input, got)
		}
	}
	if identityMigrationAssignmentStatus("active") != "active" || identityMigrationAssignmentStatus("terminated") != "disabled" {
		t.Fatal("assignment status mapping")
	}
	for _, fact := range []legacyIdentityUserWorkforceFacts{
		{DepartmentID: "department"}, {ManagerID: "manager"}, {JobTitle: "title"}, {JobLevel: "level"},
	} {
		if !identityMigrationNeedsAssignment(fact) {
			t.Fatalf("assignment fact not detected: %#v", fact)
		}
	}
	if identityMigrationNeedsAssignment(legacyIdentityUserWorkforceFacts{}) {
		t.Fatal("empty facts require assignment")
	}
	if identityMigrationNullable(" ") != nil || identityMigrationNullable("value") != "value" {
		t.Fatal("nullable mapping")
	}
	if identityMigrationString(nil) != "" || identityMigrationString([]byte("bytes")) != "bytes" ||
		identityMigrationString("text") != "text" || identityMigrationString(12) != "12" {
		t.Fatal("SQL value conversion")
	}
	if identityMigrationID("kind", "a") == identityMigrationID("kind", "b") ||
		identityMigrationUserKey("workspace", "user") != "workspace\x00user" {
		t.Fatal("migration identity")
	}
}

func TestIdentityMigrationTableInspectionEdges(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			columnStep := schemaSQLQueryStep{}
			indexStep := schemaSQLQueryStep{}
			if dialect == "sqlite" {
				columnStep = schemaSQLQueryStep{
					columns: []string{"cid", "name", "type", "notnull", "default", "pk"},
					rows:    [][]driver.Value{{int64(0), "employee_no", "TEXT", int64(0), nil, int64(0)}},
				}
			} else {
				columnStep = schemaSQLQueryStep{columns: []string{"name"}, rows: [][]driver.Value{{"employee_no"}}}
			}
			indexStep = schemaSQLQueryStep{columns: []string{"name"}, rows: [][]driver.Value{{"idx_identity_users_department"}}}
			store, closeDB := schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{columnStep, indexStep}}, dialect)
			columns, err := store.TableColumns(t.Context(), "identity_users")
			if err != nil || !columns["employee_no"] {
				t.Fatalf("columns=%v err=%v", columns, err)
			}
			indexes, err := store.TableIndexes(t.Context(), "identity_users")
			if err != nil || !indexes["idx_identity_users_department"] {
				t.Fatalf("indexes=%v err=%v", indexes, err)
			}
			closeDB()
		})
	}
	for _, inspect := range []func(scriptedSchemaStore) error{
		func(store scriptedSchemaStore) error {
			_, err := store.TableColumns(t.Context(), "identity_users")
			return err
		},
		func(store scriptedSchemaStore) error {
			_, err := store.TableIndexes(t.Context(), "identity_users")
			return err
		},
	} {
		store, closeDB := schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}})
		if err := inspect(store); err == nil {
			t.Fatal("inspection query failure ignored")
		}
		closeDB()
		store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{
			columns: []string{"first", "second"}, rows: [][]driver.Value{{"a", "b"}},
		}}})
		if err := inspect(store); err == nil {
			t.Fatal("inspection scan failure ignored")
		}
		closeDB()
		store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{
			columns: []string{"name"}, nextErr: errSchemaSQL,
		}}})
		if err := inspect(store); err == nil {
			t.Fatal("inspection iteration failure ignored")
		}
		closeDB()
	}
	store, closeDB := schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{
		columns: []string{"first", "second"}, rows: [][]driver.Value{{"a", "b"}},
	}}}, "mysql")
	if _, err := store.TableColumns(t.Context(), "identity_users"); err == nil {
		t.Fatal("non-sqlite column scan failure ignored")
	}
	closeDB()
}

func TestLoadLegacyIdentityWorkforceFactsEdges(t *testing.T) {
	store, closeDB := schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}})
	if _, err := loadLegacyIdentityUserWorkforceFacts(t.Context(), store, map[string]bool{"employee_no": true}); err == nil {
		t.Fatal("legacy query failure ignored")
	}
	closeDB()
	store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{
		columns: []string{"only"}, rows: [][]driver.Value{{"value"}},
	}}})
	if _, err := loadLegacyIdentityUserWorkforceFacts(t.Context(), store, nil); err == nil {
		t.Fatal("legacy scan failure ignored")
	}
	closeDB()
	store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{
		columns: make([]string, 15), nextErr: errSchemaSQL,
	}}})
	if _, err := loadLegacyIdentityUserWorkforceFacts(t.Context(), store, nil); err == nil {
		t.Fatal("legacy iteration failure ignored")
	}
	closeDB()
	values := make([]driver.Value, 15)
	values[0], values[1], values[2], values[3] = []byte("user"), "workspace", int64(12), nil
	store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{
		columns: make([]string, 15), rows: [][]driver.Value{values},
	}}})
	facts, err := loadLegacyIdentityUserWorkforceFacts(t.Context(), store, map[string]bool{"employee_no": true})
	if err != nil || len(facts) != 1 || facts[0].UserID != "user" || facts[0].EmployeeNo != "12" {
		t.Fatalf("facts=%#v err=%v", facts, err)
	}
	closeDB()
}

func TestMigrateLegacyIdentityWorkforceFactsStages(t *testing.T) {
	columnStep := schemaSQLQueryStep{
		columns: []string{"cid", "name", "type", "notnull", "default", "pk"},
		rows:    [][]driver.Value{{int64(0), "employee_no", "TEXT", int64(0), nil, int64(0)}},
	}
	for _, state := range []*schemaSQLState{
		{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{columnStep, {err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{columnStep, {columns: make([]string, 15)}}, beginErr: errSchemaSQL},
		{querySteps: []schemaSQLQueryStep{columnStep, {columns: make([]string, 15)}, {err: errSchemaSQL}}},
		{
			querySteps: []schemaSQLQueryStep{
				columnStep, {columns: make([]string, 15)}, {columns: []string{"name"}},
			},
			execSteps: []schemaSQLExecStep{{err: errSchemaSQL}},
		},
	} {
		store, closeDB := schemaStoreForState(state)
		if err := migrateLegacyIdentityUserWorkforceFacts(t.Context(), store); err == nil {
			t.Fatalf("migration failure ignored: %#v", state)
		}
		closeDB()
	}
	store, closeDB := schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{columns: columnStep.columns}}})
	if err := migrateLegacyIdentityUserWorkforceFacts(t.Context(), store); err != nil {
		t.Fatalf("schema without legacy columns: %v", err)
	}
	closeDB()
	for _, legacyColumn := range []string{"department_id", "manager_id"} {
		step := columnStep
		step.rows = [][]driver.Value{{int64(0), legacyColumn, "TEXT", int64(0), nil, int64(0)}}
		store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{step, {columns: make([]string, 15)}, {columns: []string{"name"}}}})
		if err := migrateLegacyIdentityUserWorkforceFacts(t.Context(), store); err != nil {
			t.Fatalf("empty %s migration: %v", legacyColumn, err)
		}
		closeDB()
	}
	store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{
		columnStep, {columns: make([]string, 15)}, {columns: []string{"name"}},
	}})
	if err := migrateLegacyIdentityUserWorkforceFacts(t.Context(), store); err != nil {
		t.Fatalf("empty migration: %v", err)
	}
	closeDB()
}

func TestPersistLegacyIdentityWorkforceFactsFailureStages(t *testing.T) {
	fact := legacyIdentityUserWorkforceFacts{UserID: "user", WorkspaceID: "workspace"}
	store, closeDB := schemaStoreForState(&schemaSQLState{beginErr: errSchemaSQL})
	if err := persistLegacyIdentityUserWorkforceFacts(t.Context(), store, []legacyIdentityUserWorkforceFacts{fact}); err == nil {
		t.Fatal("begin failure ignored")
	}
	closeDB()

	for _, state := range []*schemaSQLState{
		{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{{}}, execSteps: []schemaSQLExecStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{
			{columns: []string{"id"}, rows: [][]driver.Value{{"profile"}}},
			{err: errSchemaSQL},
		}},
		{querySteps: []schemaSQLQueryStep{
			{columns: []string{"id"}, rows: [][]driver.Value{{"profile"}}},
			{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}},
		}, execSteps: []schemaSQLExecStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{
			{columns: []string{"id"}, rows: [][]driver.Value{{"profile"}}},
			{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
		}, commitErr: errSchemaSQL},
	} {
		store, closeDB = schemaStoreForState(state)
		if err := persistLegacyIdentityUserWorkforceFacts(t.Context(), store, []legacyIdentityUserWorkforceFacts{fact}); err == nil {
			t.Fatalf("persistence failure ignored: %#v", state)
		}
		closeDB()
	}
	store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{
		{columns: []string{"id"}, rows: [][]driver.Value{{"profile"}}},
		{err: errSchemaSQL},
	}})
	if err := persistLegacyIdentityUserWorkforceFacts(t.Context(), store, []legacyIdentityUserWorkforceFacts{{
		UserID: "user", WorkspaceID: "workspace", JobTitle: "Engineer",
	}}); err == nil {
		t.Fatal("assignment orchestration failure ignored")
	}
	closeDB()

	manager := legacyIdentityUserWorkforceFacts{UserID: "manager", WorkspaceID: "workspace"}
	report := legacyIdentityUserWorkforceFacts{
		UserID: "report", WorkspaceID: "workspace", ManagerID: "manager", DepartmentID: "department",
	}
	store, closeDB = schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{
		{columns: []string{"id"}, rows: [][]driver.Value{{"manager-profile"}}},
		{columns: []string{"id"}, rows: [][]driver.Value{{"report-profile"}}},
		{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
		{columns: []string{"id"}, rows: [][]driver.Value{{"assignment"}}},
		{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}},
	}})
	if err := persistLegacyIdentityUserWorkforceFacts(t.Context(), store, []legacyIdentityUserWorkforceFacts{manager, report}); err != nil {
		t.Fatalf("manager migration: %v", err)
	}
	closeDB()
}

func TestEnsureLegacyWorkforceProfileAndAssignmentEdges(t *testing.T) {
	fact := legacyIdentityUserWorkforceFacts{UserID: "user", WorkspaceID: "workspace", JobTitle: "Engineer"}
	withTx := func(t *testing.T, state *schemaSQLState, call func(*sql.Tx, scriptedSchemaStore) error) error {
		t.Helper()
		store, closeDB := schemaStoreForState(state)
		defer closeDB()
		tx, err := store.db.BeginTx(t.Context(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		return call(tx, store)
	}
	profileCall := func(tx *sql.Tx, store scriptedSchemaStore) error {
		_, err := ensureLegacyWorkforceProfile(t.Context(), tx, store, fact)
		return err
	}
	for _, state := range []*schemaSQLState{
		{querySteps: []schemaSQLQueryStep{{columns: []string{"id"}, rows: [][]driver.Value{{"existing"}}}}},
		{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{{}}, execSteps: []schemaSQLExecStep{{err: errSchemaSQL}}},
	} {
		err := withTx(t, state, profileCall)
		if state.querySteps != nil && err == nil && len(state.execSteps) > 0 {
			t.Fatal("profile insert failure ignored")
		}
		if state.querySteps != nil && len(state.querySteps) > 0 && state.querySteps[0].err != nil && err == nil {
			t.Fatal("profile query failure ignored")
		}
	}
	if err := withTx(t, &schemaSQLState{querySteps: []schemaSQLQueryStep{{}}}, profileCall); err != nil {
		t.Fatalf("new profile: %v", err)
	}

	assignmentCall := func(tx *sql.Tx, store scriptedSchemaStore) error {
		_, err := ensureLegacyWorkforceAssignment(t.Context(), tx, store, fact, "profile", "")
		return err
	}
	for _, state := range []*schemaSQLState{
		{querySteps: []schemaSQLQueryStep{{columns: []string{"id"}, rows: [][]driver.Value{{"existing"}}}}},
		{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{{}}, execSteps: []schemaSQLExecStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{{}}, execSteps: []schemaSQLExecStep{{}, {err: errSchemaSQL}}},
	} {
		err := withTx(t, state, assignmentCall)
		if (state.querySteps != nil || state.execSteps != nil) && (len(state.querySteps) > 0 && state.querySteps[0].err != nil || len(state.execSteps) > 0 && state.execSteps[len(state.execSteps)-1].err != nil) && err == nil {
			t.Fatal("assignment failure ignored")
		}
	}
	if err := withTx(t, &schemaSQLState{querySteps: []schemaSQLQueryStep{{}}}, assignmentCall); err != nil {
		t.Fatalf("new assignment: %v", err)
	}
	levelOnly := fact
	levelOnly.JobTitle, levelOnly.JobLevel = "", "L1"
	if err := withTx(t, &schemaSQLState{querySteps: []schemaSQLQueryStep{{}}}, func(tx *sql.Tx, store scriptedSchemaStore) error {
		_, err := ensureLegacyWorkforceAssignment(t.Context(), tx, store, levelOnly, "profile", "")
		return err
	}); err != nil {
		t.Fatalf("level-only assignment: %v", err)
	}
}

func TestEnsureLegacyWorkforceReceiptEdges(t *testing.T) {
	fact := legacyIdentityUserWorkforceFacts{UserID: "user", WorkspaceID: "workspace"}
	target := legacyIdentityUserWorkforceTarget{profileID: "profile"}
	for _, state := range []*schemaSQLState{
		{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}}}},
		{querySteps: []schemaSQLQueryStep{{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}}}, execSteps: []schemaSQLExecStep{{err: errSchemaSQL}}},
		{querySteps: []schemaSQLQueryStep{{columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}}}},
	} {
		wantErr := state.querySteps != nil && len(state.querySteps) > 0 && state.querySteps[0].err != nil ||
			len(state.execSteps) > 0 && state.execSteps[0].err != nil
		store, closeDB := schemaStoreForState(state)
		tx, err := store.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		callErr := ensureLegacyWorkforceMigrationReceipt(t.Context(), tx, store, fact, target)
		_ = tx.Rollback()
		closeDB()
		if wantErr != (callErr != nil) {
			t.Fatalf("receipt error=%v wantErr=%v", callErr, wantErr)
		}
	}
}

func TestDropLegacyWorkforceIndexesEdges(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql"} {
		store, closeDB := schemaStoreForState(&schemaSQLState{
			querySteps: []schemaSQLQueryStep{{
				columns: []string{"name"}, rows: [][]driver.Value{{"idx_identity_users_department"}},
			}},
			execSteps: []schemaSQLExecStep{{err: errSchemaSQL}},
		}, dialect)
		if err := dropLegacyIdentityUserWorkforceIndexes(t.Context(), store); err == nil {
			t.Fatalf("%s index drop failure ignored", dialect)
		}
		closeDB()
	}
	store, closeDB := schemaStoreForState(&schemaSQLState{querySteps: []schemaSQLQueryStep{{err: errSchemaSQL}}})
	if err := dropLegacyIdentityUserWorkforceIndexes(t.Context(), store); err == nil {
		t.Fatal("index inspection failure ignored")
	}
	closeDB()
}
