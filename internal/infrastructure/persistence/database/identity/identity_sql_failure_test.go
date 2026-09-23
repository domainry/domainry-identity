package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
)

func TestSQLIdentityDialectAndConstructorEdges(t *testing.T) {
	mysqlEngine := mysql.NewEngine()
	mysqlStore := &SQLIdentityStore{renderer: mysqlEngine.SQLDialect().WithSchema(""), engine: mysqlEngine}
	if mysqlStore.sqlRenderer().Identifier("id") != "`id`" || mysqlStore.sqlRenderer().Placeholder(1) != "?" {
		t.Fatal("mysql dialect")
	}
	postgresEngine := postgres.NewEngine()
	postgresRenderer, _ := postgresEngine.SQLDialect().WithNamespace("tenant", "")
	postgresStore := &SQLIdentityStore{renderer: postgresRenderer, engine: postgresEngine}
	if postgresStore.sqlRenderer().Placeholder(2) != "$2" || postgresStore.sqlRenderer().Table("users") != `"tenant"."users"` {
		t.Fatal("postgres dialect")
	}
	if postgresEngine.SQLDialect().WithSchema("").Table("users") != `"users"` {
		t.Fatal("empty postgres schema")
	}
	db := sql.OpenDB(identitySQLConnector{state: &identitySQLState{execFailAt: 1, failure: errors.New("unexpected repository schema write")}})
	defer db.Close()
	if _, err := NewSQLIdentityStore(t.Context(), db, mysqlEngine); err != nil {
		t.Fatalf("repository constructor performed schema IO: %v", err)
	}
}

func TestSQLIdentityStoreConstructorDoesNotMutateSchema(t *testing.T) {
	appState := &identitySQLState{}
	schemaState := &identitySQLState{}
	appDB := sql.OpenDB(identitySQLConnector{state: appState})
	schemaDB := sql.OpenDB(identitySQLConnector{state: schemaState})
	t.Cleanup(func() {
		_ = appDB.Close()
		_ = schemaDB.Close()
	})
	store, err := NewSQLIdentityStoreWithSchema(t.Context(), appDB, schemaDB, postgres.NewEngine(), "public")
	if err != nil {
		t.Fatal(err)
	}
	if appState.execCount != 0 || schemaState.execCount != 0 {
		t.Fatalf("application execs=%d schema execs=%d", appState.execCount, schemaState.execCount)
	}
	if store == nil {
		t.Fatal("nil Identity store")
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
	organizationUnit := identitymodel.IdentityOrganizationUnit{ID: "organizationUnit"}
	user := identitymodel.IdentityUser{ID: "user"}
	role := identitymodel.IdentityRole{ID: "role"}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role"}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	defer closeDB()
	if err := store.UpsertIdentityOrganizationUnit(t.Context(), "workspace-primary", identitymodel.IdentityOrganizationUnit{}); err == nil {
		t.Fatal("empty organizationUnit accepted")
	}
	if err := store.UpsertIdentityUser(t.Context(), "workspace-primary", identitymodel.IdentityUser{}); err == nil {
		t.Fatal("empty user accepted")
	}
	if err := store.UpsertIdentityRole(t.Context(), "workspace-primary", identitymodel.IdentityRole{}); err == nil {
		t.Fatal("empty role accepted")
	}
	for _, invalid := range []identitymodel.IdentityUserRoleAssignment{{}, {UserID: "user"}} {
		if err := store.AssignIdentityUserRole(t.Context(), "workspace-primary", invalid); err == nil {
			t.Fatal("invalid assignment accepted")
		}
	}
	expiresAt := "2030-01-02T03:04:05Z"
	if err := store.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{
		UserID: "expiring-user", RoleID: "role", ExpiresAt: &expiresAt,
	}); err != nil {
		t.Fatalf("assign role with expiration: %v", err)
	}
	callWithFailure(t, 1, func(s *SQLIdentityStore) error {
		return s.UpsertIdentityOrganizationUnit(t.Context(), "workspace-primary", organizationUnit)
	})
	callWithFailure(t, 1, func(s *SQLIdentityStore) error { return s.UpsertIdentityUser(t.Context(), "workspace-primary", user) })
	callWithFailure(t, 1, func(s *SQLIdentityStore) error {
		return s.AssignIdentityUserRole(t.Context(), "workspace-primary", assignment)
	})
	for failAt := 1; failAt <= 6; failAt++ {
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.RemoveIdentityUser(t.Context(), "workspace-primary", "user") })
	}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.RemoveIdentityUser(t.Context(), "workspace-primary", "user"); err == nil {
			t.Fatal("atomic user removal transaction failure ignored")
		}
		closeDB()
	}
	for failAt := 1; failAt <= 3; failAt++ {
		callWithFailure(t, failAt, func(s *SQLIdentityStore) error { return s.RemoveIdentityRole(t.Context(), "workspace-primary", "role") })
	}
	callWithFailure(t, 1, func(s *SQLIdentityStore) error {
		return s.SetIdentityUserStatus(t.Context(), "workspace-primary", "user", identitymodel.IdentityStatusActive)
	})
	callWithFailure(t, 1, func(s *SQLIdentityStore) error {
		return s.RemoveIdentityUserRole(t.Context(), "workspace-primary", "user", "role")
	})
	callWithFailure(t, 1, func(s *SQLIdentityStore) error { return s.UpsertIdentityRole(t.Context(), "workspace-primary", role) })
}

func TestSQLIdentityAtomicUserStages(t *testing.T) {
	wantErr := errors.New("atomic failure")
	user := identitymodel.IdentityUser{ID: "user"}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.UpsertIdentityUsersAtomically(t.Context(), "workspace-primary", []identitymodel.IdentityUser{user}); err == nil {
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
	if _, err := store.ListIdentityProfileBindingsByUser(t.Context(), "workspace-primary", "user"); !errors.Is(err, wantErr) {
		t.Fatalf("profile-binding query error=%v", err)
	}
	closeDB()

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"workspace_id"},
		rows:    [][]driver.Value{{"workspace-primary"}},
	}}})
	if _, err := store.ListIdentityProfileBindingsByUser(t.Context(), "workspace-primary", "user"); err == nil {
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
		{execFailAt: 2, failure: wantErr},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if err := store.UpsertIdentityUserWithRoleAssignmentsAtomically(t.Context(), "workspace-primary", user, nil); err == nil {
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
		if _, err := store.DisableIdentityAccount(t.Context(), "workspace-primary", "user"); err == nil {
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
		if _, err := store.CreateIdentityRoleRequest(t.Context(), "workspace-primary", request); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if err := store.UpdateIdentityRoleRequest(t.Context(), "workspace-primary", identitymodel.IdentityRoleRequest{}); err == nil {
		t.Fatal("empty request update accepted")
	}
	if err := store.UpsertIdentityMenu(t.Context(), "workspace-primary", identitymodel.IdentityMenu{}); err == nil {
		t.Fatal("empty menu accepted")
	}
	closeDB()
	for _, test := range []struct {
		failAt int
		call   func(*SQLIdentityStore) error
	}{
		{1, func(s *SQLIdentityStore) error {
			_, err := s.CreateIdentityRoleRequest(t.Context(), "workspace-primary", validRequest)
			return err
		}},
		{1, func(s *SQLIdentityStore) error {
			return s.UpdateIdentityRoleRequest(t.Context(), "workspace-primary", validRequest)
		}},
		{1, func(s *SQLIdentityStore) error {
			return s.UpsertIdentityMenu(t.Context(), "workspace-primary", identitymodel.IdentityMenu{ID: "menu"})
		}},
		{1, func(s *SQLIdentityStore) error {
			return s.SetIdentityRoleMenus(t.Context(), "workspace-primary", "role", []string{"menu"})
		}},
		{2, func(s *SQLIdentityStore) error {
			return s.SetIdentityRoleMenus(t.Context(), "workspace-primary", "role", []string{"menu"})
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
		{rowsFailAt: 1, failure: wantErr},
		{rowsZeroAt: 1},
		{commitErr: wantErr},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if err := store.ApplyIdentityRoleRequestDecision(t.Context(), "workspace-primary", request, nil, "pending"); err == nil {
			t.Fatalf("decision failure stage was ignored: %#v", state)
		}
		closeDB()
	}

}

func TestSQLIdentityLoaderFailureStages(t *testing.T) {
	wantErr := errors.New("loader failure")
	tests := []struct {
		name    string
		columns int
		call    func(*SQLIdentityStore) error
	}{
		{"roles", 5, func(s *SQLIdentityStore) error { _, err := s.loadRoles(t.Context(), "workspace-primary"); return err }},
		{"assignments", 4, func(s *SQLIdentityStore) error {
			_, err := s.loadUserRoleAssignments(t.Context(), "workspace-primary", "user")
			return err
		}},
		{"requests", 13, func(s *SQLIdentityStore) error {
			_, err := s.loadRoleRequests(t.Context(), "workspace-primary", "status", "user")
			return err
		}},
		{"menus", 10, func(s *SQLIdentityStore) error { _, err := s.loadMenus(t.Context(), "workspace-primary"); return err }},
		{"menu assignments", 2, func(s *SQLIdentityStore) error {
			_, err := s.loadRoleMenuAssignments(t.Context(), "workspace-primary", "role")
			return err
		}},
		{"organizationUnits", 8, func(s *SQLIdentityStore) error {
			_, err := s.loadOrganizationUnits(t.Context(), "workspace-primary")
			return err
		}},
		{"users", 18, func(s *SQLIdentityStore) error { _, err := s.loadUsers(t.Context(), "workspace-primary"); return err }},
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
	organizationUnit := identitymodel.IdentityOrganizationUnit{ID: "organizationUnit"}
	user := identitymodel.IdentityUser{ID: "user"}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: "user", RoleID: "role"}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 2, failure: wantErr}, {execFailAt: 3, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.ApplyIdentityBootstrapAtomically(t.Context(), "workspace-primary", []identitymodel.IdentityOrganizationUnit{organizationUnit}, []identitymodel.IdentityUser{user}, []identitymodel.IdentityUserRoleAssignment{assignment}); err == nil {
			t.Fatal("bootstrap failure ignored")
		}
		closeDB()
	}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.ApplyIdentityBootstrapAtomically(t.Context(), "workspace-primary", []identitymodel.IdentityOrganizationUnit{organizationUnit}, []identitymodel.IdentityUser{user}, []identitymodel.IdentityUserRoleAssignment{assignment}); err != nil {
		t.Fatal(err)
	}
	closeDB()
	menus := []identitymodel.IdentityMenu{{ID: "menu", Key: "key"}}
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 2, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		if err := store.RemoveIdentityMenusAtomically(t.Context(), "workspace-primary", menus); err == nil {
			t.Fatal("menu atomic failure ignored")
		}
		closeDB()
	}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if err := store.RemoveIdentityMenusAtomically(t.Context(), "workspace-primary", menus); err != nil {
		t.Fatal(err)
	}
	closeDB()
}

func TestSQLIdentityRoleReadStages(t *testing.T) {
	wantErr := errors.New("permission stage")
	roleColumns := []string{"id", "key", "label", "description", "status"}
	roleRow := []driver.Value{"role", "role", "Role", "", "active"}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr, querySteps: []identitySQLQueryStep{{columns: roleColumns, rows: [][]driver.Value{roleRow}}}})
	if _, err := store.ListIdentityRoles(t.Context(), "workspace-primary"); err == nil {
		t.Fatal("role query failure ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if _, _, err := store.memoryRole(t.Context(), "workspace-primary", "role"); err == nil {
		t.Fatal("memory role error ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{})
	if _, found, err := store.memoryRole(t.Context(), "workspace-primary", "role"); err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: roleColumns, rows: [][]driver.Value{{"other", "other", "Other", "", "active"}}},
	}})
	if _, found, err := store.memoryRole(t.Context(), "workspace-primary", "role"); err != nil || found {
		t.Fatalf("other role found=%v err=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		{columns: roleColumns, rows: [][]driver.Value{roleRow}},
	}})
	if role, found, err := store.memoryRole(t.Context(), "workspace-primary", "role"); err != nil || !found || role.ID != "role" {
		t.Fatalf("role=%#v found=%v err=%v", role, found, err)
	}
	closeDB()
}

func TestSQLIdentityRemainingWriteAndMenuStages(t *testing.T) {
	wantErr := errors.New("remaining SQL stage")
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if err := store.ApplyIdentityBootstrapAtomically(t.Context(), "", nil, nil, nil); err == nil {
		t.Fatal("invalid bootstrap workspace accepted")
	}
	if err := store.writeIdentityOrganizationUnit(t.Context(), store.db, "workspace-primary", identitymodel.IdentityOrganizationUnit{ID: "organizationUnit"}); err != nil {
		t.Fatal(err)
	}
	if err := store.writeIdentityUser(t.Context(), store.db, "workspace-primary", identitymodel.IdentityUser{ID: "user"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUsersAtomically(t.Context(), "workspace-primary", []identitymodel.IdentityUser{{ID: "user"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityUser(t.Context(), "workspace-primary", "user"); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityRole(t.Context(), "workspace-primary", "role"); err != nil {
		t.Fatal(err)
	}
	request := identitymodel.IdentityRoleRequest{ID: "request", UserID: "user", RoleIDs: []string{"role"}}
	if _, err := store.CreateIdentityRoleRequest(t.Context(), "workspace-primary", request); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateIdentityRoleRequest(t.Context(), "workspace-primary", request); err != nil {
		t.Fatal(err)
	}
	request.ID, request.CreatedAt, request.Status, request.UpdatedAt = "fixed-request", "created", "approved", "updated"
	if _, err := store.CreateIdentityRoleRequest(t.Context(), "workspace-primary", request); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateIdentityRoleRequest(t.Context(), "workspace-primary", request); err != nil {
		t.Fatal(err)
	}
	role := identitymodel.IdentityRole{ID: "role", Key: "key", Status: identitymodel.IdentityStatusActive}
	if err := store.UpsertIdentityRole(t.Context(), "workspace-primary", role); err != nil {
		t.Fatal(err)
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if _, err := store.loadRoleRequests(t.Context(), "workspace-primary", "", ""); err == nil {
		t.Fatal("role request query failure ignored")
	}
	closeDB()

	menuColumns := []string{"id", "key", "label", "description", "route", "icon", "parent", "sort", "status"}
	menuRow := []driver.Value{"menu", "key", "Menu", "", "/menu", "", nil, int64(1), "active"}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if err := store.UpsertIdentityMenu(t.Context(), "workspace-primary", identitymodel.IdentityMenu{ID: "menu"}); err == nil {
		t.Fatal("menu pre-read failure ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{queryFailAt: 1, failure: wantErr})
	if err := store.RemoveIdentityMenu(t.Context(), "workspace-primary", "menu"); err == nil {
		t.Fatal("menu list failure ignored")
	}
	closeDB()
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: menuColumns}}})
	if err := store.RemoveIdentityMenu(t.Context(), "workspace-primary", "missing"); err == nil {
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
		if err := store.RemoveIdentityMenu(t.Context(), "workspace-primary", "menu"); err == nil {
			t.Fatal("menu stage failure ignored")
		}
		closeDB()
	}
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{menuRow}}}})
	if err := store.RemoveIdentityMenu(t.Context(), "workspace-primary", "menu"); err != nil {
		t.Fatal(err)
	}
	closeDB()
	otherMenu := append([]driver.Value(nil), menuRow...)
	otherMenu[0], otherMenu[1] = "other", "other"
	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: menuColumns, rows: [][]driver.Value{otherMenu, menuRow}}}})
	if err := store.RemoveIdentityMenu(t.Context(), "workspace-primary", "menu"); err != nil {
		t.Fatal(err)
	}
	closeDB()
}

func TestIdentitySubjectLifecycleSQLStages(t *testing.T) {
	wantErr := errors.New("subject lifecycle stage")
	for _, state := range []*identitySQLState{{beginErr: wantErr}, {execFailAt: 1, failure: wantErr}, {execFailAt: 6, failure: wantErr}, {rowsFailAt: 6, failure: wantErr}, {commitErr: wantErr}} {
		store, closeDB := scriptedSQLIdentity(state)
		store.BindSubjectLifecyclePersistence()
		lifecycle := NewIdentitySubjectLifecycleStore(store, func(context.Context, *sql.Tx, string, string, string) error { return nil })
		if _, err := lifecycle.EraseSubject(t.Context(), "workspace-primary", "user", nil); err == nil {
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
	lifecycle := NewIdentitySubjectLifecycleStore(store, func(context.Context, *sql.Tx, string, string, string) error { return nil })
	if _, err := lifecycle.ExportSubject(t.Context(), "workspace-primary", "user"); err == nil {
		t.Fatal("export preview failure ignored")
	}
	closeDB()
}
