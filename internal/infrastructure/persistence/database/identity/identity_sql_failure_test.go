package identity

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestSQLIdentityDialectAndConstructorEdges(t *testing.T) {
	mysql := &SQLIdentityStore{driver: "mysql"}
	if mysql.identifier("id") != "`id`" || mysql.placeholder(1) != "?" {
		t.Fatal("mysql dialect")
	}
	postgres := &SQLIdentityStore{driver: "postgres", schema: "tenant"}
	if postgres.placeholder(2) != "$2" || postgres.tableIdentifier("users") != `"tenant"."users"` || postgres.placeholders(2) != "$1, $2" {
		t.Fatal("postgres dialect")
	}
	postgres.schema = " "
	if postgres.tableIdentifier("users") != `"users"` {
		t.Fatal("empty postgres schema")
	}
	db := sql.OpenDB(identitySQLConnector{state: &identitySQLState{execFailAt: 1, failure: errors.New("schema")}})
	defer db.Close()
	if _, err := NewSQLIdentityStore(t.Context(), db, "mysql"); err == nil {
		t.Fatal("constructor schema failure ignored")
	}
}

func TestSQLIdentityRoleRequestSchemaUsesDedicatedDatabase(t *testing.T) {
	appState := &identitySQLState{}
	schemaState := &identitySQLState{}
	appDB := sql.OpenDB(identitySQLConnector{state: appState})
	schemaDB := sql.OpenDB(identitySQLConnector{state: schemaState})
	t.Cleanup(func() {
		_ = appDB.Close()
		_ = schemaDB.Close()
	})
	store, err := NewSQLIdentityStoreWithSchema(t.Context(), appDB, schemaDB, "postgres", "public")
	if err != nil {
		t.Fatal(err)
	}
	if appState.execCount != 0 || schemaState.execCount != 2 {
		t.Fatalf("application execs=%d schema execs=%d", appState.execCount, schemaState.execCount)
	}
	if err := store.ensureRoleRequestsTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	if appState.execCount != 0 || schemaState.execCount != 2 {
		t.Fatalf("repeated ensure application execs=%d schema execs=%d", appState.execCount, schemaState.execCount)
	}
}

func TestSQLIdentityUserAndRoleWriteStages(t *testing.T) {
	wantErr := errors.New("identity SQL failure")
	callWithFailure := func(t *testing.T, failAt int, call func(*SQLIdentityStore) error) {
		t.Helper()
		store, closeDB := scriptedSQLIdentity(&identitySQLState{execFailAt: failAt, failure: wantErr})
		defer closeDB()
		if err := call(store); err == nil {
			t.Fatalf("exec failure %d ignored", failAt)
		}
	}
	department := identitymodel.IdentityDepartment{ID: "department"}
	user := identitymodel.IdentityUser{ID: "user"}
	role := identitymodel.IdentityRole{ID: "role"}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role"}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	defer closeDB()
	if err := store.UpsertIdentityDepartment(t.Context(), "default", identitymodel.IdentityDepartment{}); err == nil {
		t.Fatal("empty department accepted")
	}
	if err := store.UpsertIdentityUser(t.Context(), "default", identitymodel.IdentityUser{}); err == nil {
		t.Fatal("empty user accepted")
	}
	if err := store.UpsertIdentityRole(t.Context(), "default", identitymodel.IdentityRole{}); err == nil {
		t.Fatal("empty role accepted")
	}
	for _, invalid := range []identitymodel.IdentityUserRoleAssignment{{}, {UserID: "user"}} {
		if err := store.AssignIdentityUserRole(t.Context(), "default", invalid); err == nil {
			t.Fatal("invalid assignment accepted")
		}
	}
	expiresAt := "2030-01-02T03:04:05Z"
	if err := store.AssignIdentityUserRole(t.Context(), "default", identitymodel.IdentityUserRoleAssignment{
		UserID: "expiring-user", RoleID: "role", ExpiresAt: &expiresAt,
	}); err != nil {
		t.Fatalf("assign role with expiration: %v", err)
	}
	for failAt := 1; failAt <= 2; failAt++ {
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.UpsertIdentityDepartment(t.Context(), "default", department) })
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.UpsertIdentityUser(t.Context(), "default", user) })
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.AssignIdentityUserRole(t.Context(), "default", assignment) })
	}
	for failAt := 1; failAt <= 6; failAt++ {
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.RemoveIdentityUser(t.Context(), "default", "user") })
	}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.RemoveIdentityUser(t.Context(), "default", "user"); err == nil {
			t.Fatal("atomic user removal transaction failure ignored")
		}
		closeDB()
	}
	for failAt := 1; failAt <= 3; failAt++ {
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.RemoveIdentityRole(t.Context(), "default", "role") })
	}
	callWithFailure(t, 1, func(s *SQLIdentityStore) error {
		return s.SetIdentityUserStatus(t.Context(), "default", "user", identitymodel.IdentityStatusActive)
	})
	callWithFailure(t, 1, func(s *SQLIdentityStore) error {
		return s.RemoveIdentityUserRole(t.Context(), "default", "user", "role")
	})
	for failAt := 1; failAt <= 2; failAt++ {
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.UpsertIdentityRole(t.Context(), "default", role) })
	}
}

func TestSQLIdentityAtomicUserStages(t *testing.T) {
	wantErr := errors.New("atomic failure")
	user := identitymodel.IdentityUser{ID: "user"}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 2, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.UpsertIdentityUsersAtomically(t.Context(), "default", []identitymodel.IdentityUser{user}); err == nil {
			t.Fatal("atomic user failure ignored")
		}
		closeDB()
	}
}

func TestSQLIdentityUserProfileBindingAndRoleReconcileFailureStages(t *testing.T) {
	wantErr := errors.New("user profile binding or role reconcile failure")

	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if _, err := store.ListIdentityProfileBindingsByUser(t.Context(), "", "user"); err == nil {
		t.Fatal("empty profile-binding workspace accepted")
	}
	closeDB()

	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if _, err := store.ListIdentityProfileBindingsByUser(t.Context(), "default", "user"); !errors.Is(err, wantErr) {
		t.Fatalf("profile-binding query error=%v", err)
	}
	closeDB()

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"workspace_id"},
		rows:    [][]driver.Value{{"default"}},
	}}})
	if _, err := store.ListIdentityProfileBindingsByUser(t.Context(), "default", "user"); err == nil {
		t.Fatal("profile-binding scan failure ignored")
	}
	closeDB()

	user := identitymodel.IdentityUser{ID: "user"}
	if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "", user, nil); err == nil {
		t.Fatal("empty reconcile workspace accepted")
	}
	for _, state := range []*identitySQLState{
		{beginErr: wantErr},
		{queryFailAt: 1, failure: wantErr},
		{execFailAt: 3, failure: wantErr},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "default", user, nil); err == nil {
			t.Fatalf("role reconcile failure stage ignored: %#v", state)
		}
		closeDB()
	}
}

func TestSQLIdentityAccountDisableFailureStages(t *testing.T) {
	wantErr := errors.New("account disable failure")
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if _, err := store.DisableIdentityAccount(t.Context(), "", "user"); err == nil {
		t.Fatal("empty account-disable workspace accepted")
	}
	closeDB()

	for _, state := range []*identitySQLState{
		{beginErr: wantErr},
		{execFailAt: 1, failure: wantErr},
		{rowsFailAt: 1, failure: wantErr},
		{rowsZeroAt: 1},
		{execFailAt: 2, failure: wantErr},
		{rowsFailAt: 2, failure: wantErr},
		{commitErr: wantErr},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, err := store.DisableIdentityAccount(t.Context(), "default", "user"); err == nil {
			t.Fatalf("account disable failure stage ignored: %#v", state)
		}
		closeDB()
	}
}

func TestSQLIdentityRequestAndMenuWriteStages(t *testing.T) {
	wantErr := errors.New("menu failure")
	validRequest := identitymodel.IdentityRoleRequest{ID: "request", UserID: "user", RoleIDs: []string{"role"}}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	for _, request := range []identitymodel.IdentityRoleRequest{{}, {ID: "id"}, {ID: "id", UserID: "user"}} {
		if _, err := store.CreateIdentityRoleRequest(t.Context(), "default", request); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if err := store.UpdateIdentityRoleRequest(t.Context(), "default", identitymodel.IdentityRoleRequest{}); err == nil {
		t.Fatal("empty request update accepted")
	}
	if err := store.UpsertIdentityMenu(t.Context(), "default", identitymodel.IdentityMenu{}); err == nil {
		t.Fatal("empty menu accepted")
	}
	closeDB()
	for _, test := range []struct {
		failAt int
		call   func(*SQLIdentityStore) error
	}{
		{1, func(s *SQLIdentityStore) error {
			_, err := s.CreateIdentityRoleRequest(t.Context(), "default", validRequest)
			return err
		}},
		{2, func(s *SQLIdentityStore) error {
			_, err := s.CreateIdentityRoleRequest(t.Context(), "default", validRequest)
			return err
		}},
		{3, func(s *SQLIdentityStore) error {
			_, err := s.CreateIdentityRoleRequest(t.Context(), "default", validRequest)
			return err
		}},
		{1, func(s *SQLIdentityStore) error {
			return s.UpdateIdentityRoleRequest(t.Context(), "default", validRequest)
		}},
		{1, func(s *SQLIdentityStore) error {
			return s.UpsertIdentityMenu(t.Context(), "default", identitymodel.IdentityMenu{ID: "menu"})
		}},
		{2, func(s *SQLIdentityStore) error {
			return s.UpsertIdentityMenu(t.Context(), "default", identitymodel.IdentityMenu{ID: "menu"})
		}},
		{1, func(s *SQLIdentityStore) error {
			return s.SetIdentityRoleMenus(t.Context(), "default", "role", []string{"menu"})
		}},
		{2, func(s *SQLIdentityStore) error {
			return s.SetIdentityRoleMenus(t.Context(), "default", "role", []string{"menu"})
		}},
	} {
		store, closeDB := scriptedSQLIdentity(&identitySQLState{execFailAt: test.failAt, failure: wantErr})
		if err := test.call(store); err == nil {
			t.Fatal("write failure ignored")
		}
		closeDB()
	}
}

func TestSQLIdentityRoleRequestDecisionFailureStages(t *testing.T) {
	wantErr := errors.New("role request decision failure")
	request := identitymodel.IdentityRoleRequest{ID: "request", UserID: "user", RoleIDs: []string{"role"}, Status: "approved"}

	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.ApplyIdentityRoleRequestDecision(t.Context(), "", request, nil, "pending"); err == nil {
		t.Fatal("empty workspace accepted")
	}
	closeDB()

	for _, state := range []*identitySQLState{
		{execFailAt: 1, failure: wantErr},
		{beginErr: wantErr},
		{execFailAt: 3, failure: wantErr},
		{rowsFailAt: 3, failure: wantErr},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if err := store.ApplyIdentityRoleRequestDecision(t.Context(), "default", request, nil, "pending"); err == nil {
			t.Fatalf("decision failure stage was ignored: %#v", state)
		}
		closeDB()
	}

	store, closeDB = scriptedSQLIdentity(&identitySQLState{execFailAt: 2, failure: errors.New("column already exists")})
	if err := store.ensureRoleRequestsTable(t.Context()); err != nil {
		t.Fatalf("already-existing requested_by column should be accepted: %v", err)
	}
	closeDB()
}

func TestSQLIdentityLoaderFailureStages(t *testing.T) {
	wantErr := errors.New("loader failure")
	tests := []struct {
		name    string
		columns int
		call    func(*SQLIdentityStore) error
	}{
		{"roles", 5, func(s *SQLIdentityStore) error { _, err := s.loadRoles(t.Context(), "default"); return err }},
		{"assignments", 4, func(s *SQLIdentityStore) error {
			_, err := s.loadUserRoleAssignments(t.Context(), "default", "user")
			return err
		}},
		{"requests", 13, func(s *SQLIdentityStore) error {
			_, err := s.loadRoleRequests(t.Context(), "default", "status", "user")
			return err
		}},
		{"menus", 10, func(s *SQLIdentityStore) error { _, err := s.loadMenus(t.Context(), "default"); return err }},
		{"menu assignments", 2, func(s *SQLIdentityStore) error {
			_, err := s.loadRoleMenuAssignments(t.Context(), "default", "role")
			return err
		}},
		{"departments", 8, func(s *SQLIdentityStore) error { _, err := s.loadDepartments(t.Context(), "default"); return err }},
		{"users", 18, func(s *SQLIdentityStore) error { _, err := s.loadUsers(t.Context(), "default"); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, closeDB := scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
			if err := test.call(store); err == nil {
				t.Fatal("query failure ignored")
			}
			closeDB()
			columns := make([]string, test.columns+1)
			values := make([]driver.Value, test.columns+1)
			for index := range columns {
				columns[index] = "c"
				values[index] = "v"
			}
			store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: columns, rows: [][]driver.Value{values}}}})
			if err := test.call(store); err == nil {
				t.Fatal("scan failure ignored")
			}
			closeDB()
			columns = columns[:test.columns]
			store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: columns, nextErr: wantErr}}})
			if err := test.call(store); err == nil {
				t.Fatal("rows failure ignored")
			}
			closeDB()
		})
	}
}

func TestSQLIdentityBootstrapAndMenuAtomicStages(t *testing.T) {
	wantErr := errors.New("atomic stage")
	department := identitymodel.IdentityDepartment{ID: "department"}
	user := identitymodel.IdentityUser{ID: "user"}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role"}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 3, failure: wantErr}, {execFailAt: 5, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.ApplyIdentityBootstrapAtomically(t.Context(), "default", []identitymodel.IdentityDepartment{department}, []identitymodel.IdentityUser{user}, nil, nil, []identitymodel.IdentityUserRoleAssignment{assignment}); err == nil {
			t.Fatal("bootstrap failure ignored")
		}
		closeDB()
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.ApplyIdentityBootstrapAtomically(t.Context(), "default", []identitymodel.IdentityDepartment{department}, []identitymodel.IdentityUser{user}, nil, nil, []identitymodel.IdentityUserRoleAssignment{assignment}); err != nil {
		t.Fatal(err)
	}
	closeDB()
	menus := []identitymodel.IdentityMenu{{ID: "menu", Key: "key"}}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 2, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.RemoveIdentityMenusAtomically(t.Context(), "default", menus); err == nil {
			t.Fatal("menu atomic failure ignored")
		}
		closeDB()
	}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if err := store.RemoveIdentityMenusAtomically(t.Context(), "default", menus); err != nil {
		t.Fatal(err)
	}
	closeDB()
}

func TestSQLIdentityRoleReadStages(t *testing.T) {
	wantErr := errors.New("permission stage")
	roleColumns := []string{"id", "key", "label", "description", "status"}
	roleRow := []driver.Value{"role", "role", "Role", "", "active"}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr, querySteps: []identitySQLQueryStep{{columns: roleColumns, rows: [][]driver.Value{roleRow}}}})
	if _, err := store.ListIdentityRoles(t.Context(), "default"); err == nil {
		t.Fatal("role query failure ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if _, _, err := store.memoryRole(t.Context(), "default", "role"); err == nil {
		t.Fatal("memory role error ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if _, found, err := store.memoryRole(t.Context(), "default", "role"); err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: roleColumns, rows: [][]driver.Value{{"other", "other", "Other", "", "active"}}},
	}})
	if _, found, err := store.memoryRole(t.Context(), "default", "role"); err != nil || found {
		t.Fatalf("other role found=%v err=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: roleColumns, rows: [][]driver.Value{roleRow}},
	}})
	if role, found, err := store.memoryRole(t.Context(), "default", "role"); err != nil || !found || role.ID != "role" {
		t.Fatalf("role=%#v found=%v err=%v", role, found, err)
	}
	closeDB()
}

func TestSQLIdentityRemainingWriteAndMenuStages(t *testing.T) {
	wantErr := errors.New("remaining SQL stage")
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.ApplyIdentityBootstrapAtomically(t.Context(), "", nil, nil, nil, nil, nil); err == nil {
		t.Fatal("invalid bootstrap workspace accepted")
	}
	if err := store.writeIdentityDepartment(t.Context(), store.db, "default", identitymodel.IdentityDepartment{ID: "department"}); err != nil {
		t.Fatal(err)
	}
	if err := store.writeIdentityUser(t.Context(), store.db, "default", identitymodel.IdentityUser{ID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUsersAtomically(t.Context(), "default", []identitymodel.IdentityUser{{ID: "user"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityUser(t.Context(), "default", "user"); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityRole(t.Context(), "default", "role"); err != nil {
		t.Fatal(err)
	}
	request := identitymodel.IdentityRoleRequest{ID: "request", UserID: "user", RoleIDs: []string{"role"}}
	if _, err := store.CreateIdentityRoleRequest(t.Context(), "default", request); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateIdentityRoleRequest(t.Context(), "default", request); err != nil {
		t.Fatal(err)
	}
	request.ID, request.CreatedAt, request.Status, request.UpdatedAt = "fixed-request", "created", "approved", "updated"
	if _, err := store.CreateIdentityRoleRequest(t.Context(), "default", request); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateIdentityRoleRequest(t.Context(), "default", request); err != nil {
		t.Fatal(err)
	}
	role := identitymodel.IdentityRole{ID: "role", Key: "key", Status: identitymodel.IdentityStatusActive}
	if err := store.UpsertIdentityRole(t.Context(), "default", role); err != nil {
		t.Fatal(err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{execFailAt: 1, failure: wantErr})
	if _, err := store.loadRoleRequests(t.Context(), "default", "", ""); err == nil {
		t.Fatal("role request schema failure ignored")
	}
	closeDB()

	menuColumns := []string{"id", "key", "label", "description", "route", "icon", "parent", "sort", "status"}
	menuRow := []driver.Value{"menu", "key", "Menu", "", "/menu", "", nil, int64(1), "active"}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if err := store.UpsertIdentityMenu(t.Context(), "default", identitymodel.IdentityMenu{ID: "menu"}); err == nil {
		t.Fatal("menu pre-read failure ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if err := store.RemoveIdentityMenu(t.Context(), "default", "menu"); err == nil {
		t.Fatal("menu list failure ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: menuColumns}}})
	if err := store.RemoveIdentityMenu(t.Context(), "default", "missing"); err == nil {
		t.Fatal("missing menu removed")
	}
	closeDB()
	states := []*identitySQLState{
		{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{menuRow}}}, beginErr: wantErr},
		{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{menuRow}}}, execFailAt: 1, failure: wantErr},
		{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{menuRow}}}, execFailAt: 2, failure: wantErr},
		{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{menuRow}}}, commitErr: wantErr},
	}
	for _, state := range states {
		store, closeDB = scriptedSQLIdentity(state)
		if err := store.RemoveIdentityMenu(t.Context(), "default", "menu"); err == nil {
			t.Fatal("menu stage failure ignored")
		}
		closeDB()
	}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{menuRow}}}})
	if err := store.RemoveIdentityMenu(t.Context(), "default", "menu"); err != nil {
		t.Fatal(err)
	}
	closeDB()
	otherMenu := append([]driver.Value(nil), menuRow...)
	otherMenu[0], otherMenu[1] = "other", "other"
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{otherMenu, menuRow}}}})
	if err := store.RemoveIdentityMenu(t.Context(), "default", "menu"); err != nil {
		t.Fatal(err)
	}
	closeDB()
}

func TestIdentitySubjectLifecycleSQLStages(t *testing.T) {
	wantErr := errors.New("subject lifecycle stage")
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 6, failure: wantErr}, {rowsFailAt: 6, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		lifecycle := NewIdentitySubjectLifecycleStore(store)
		if _, err := lifecycle.EraseSubject(t.Context(), "default", "user", nil); err == nil {
			t.Fatal("erase stage failure ignored")
		}
		closeDB()
	}
	userColumns := make([]string, 14)
	userRow := make([]driver.Value, 14)
	for index := range userColumns {
		userColumns[index], userRow[index] = "c", "v"
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{queryFailAt: 2, failure: wantErr, querySteps: []identitySQLQueryStep{{columns: userColumns, rows: [][]driver.Value{userRow}}}})
	lifecycle := NewIdentitySubjectLifecycleStore(store)
	if _, err := lifecycle.ExportSubject(t.Context(), "default", "user"); err == nil {
		t.Fatal("export preview failure ignored")
	}
	closeDB()
}
