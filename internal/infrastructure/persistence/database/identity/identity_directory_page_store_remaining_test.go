package identity

import (
	"database/sql/driver"
	"reflect"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityDirectoryCountStep(total int64) identitySQLQueryStep {
	return identitySQLQueryStep{columns: []string{"count"}, rows: [][]driver.Value{{total}}}
}

func identityDirectoryUserColumns() []string {
	return []string{
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at",
	}
}

func identityDirectoryUserRow() []driver.Value {
	return []driver.Value{
		"user", "User", "", "", "", "", "", "", "",
		"user@example.test", "", "human", "en-US", "UTC", "active", int64(1), "created", "updated",
	}
}

func TestSearchIdentityUsersRemainingSQLFailures(t *testing.T) {
	query := identitymodel.IdentityListQuery{PageSize: 2, Sort: []identitymodel.IdentitySortRule{{Field: "id", Direction: "asc"}}}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if _, err := store.SearchIdentityUsers(t.Context(), "", query); err == nil {
		t.Fatal("blank workspace accepted")
	}
	closeDB()

	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{
			queryFailAt: 2, failure: errProfileBindingSQL,
			querySteps: []identitySQLQueryStep{identityDirectoryCountStep(1)},
		},
		{querySteps: []identitySQLQueryStep{
			identityDirectoryCountStep(1),
			{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
		}},
		{querySteps: []identitySQLQueryStep{
			identityDirectoryCountStep(1),
			{columns: identityDirectoryUserColumns(), nextErr: errProfileBindingSQL},
		}},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, err := store.SearchIdentityUsers(t.Context(), "workspace", query); err == nil {
			t.Fatal("user directory failure ignored")
		}
		closeDB()
	}

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		identityDirectoryCountStep(3),
		{columns: identityDirectoryUserColumns(), rows: [][]driver.Value{identityDirectoryUserRow()}},
	}})
	page, err := store.SearchIdentityUsers(t.Context(), "workspace", query)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "user" || page.HasNext || page.Total != 3 {
		t.Fatalf("user page=%#v error=%v", page, err)
	}
	closeDB()
}

func TestSearchIdentityWorkforceProfilesRemainingSQLFailures(t *testing.T) {
	query := identitymodel.IdentityListQuery{PageSize: 2, Sort: []identitymodel.IdentitySortRule{{Field: "id", Direction: "asc"}}}
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	if _, err := store.SearchIdentityWorkforceProfiles(t.Context(), "", query); err == nil {
		t.Fatal("blank workspace accepted")
	}
	closeDB()

	workforceColumns := []string{
		"id", "organization_id", "identity_user_id", "worker_no", "worker_type",
		"work_status", "start_date", "end_date", "primary_assignment_id", "version",
	}
	for _, state := range []*identitySQLState{
		{queryFailAt: 1, failure: errProfileBindingSQL},
		{
			queryFailAt: 2, failure: errProfileBindingSQL,
			querySteps: []identitySQLQueryStep{identityDirectoryCountStep(1)},
		},
		{querySteps: []identitySQLQueryStep{
			identityDirectoryCountStep(1),
			{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
		}},
		{querySteps: []identitySQLQueryStep{
			identityDirectoryCountStep(1),
			{columns: workforceColumns, nextErr: errProfileBindingSQL},
		}},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, err := store.SearchIdentityWorkforceProfiles(t.Context(), "workspace", query); err == nil {
			t.Fatal("workforce directory failure ignored")
		}
		closeDB()
	}

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		identityDirectoryCountStep(1),
		{columns: workforceColumns, rows: [][]driver.Value{workforceProfileRow()}},
	}})
	page, err := store.SearchIdentityWorkforceProfiles(t.Context(), "workspace", query)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "profile" || page.HasNext {
		t.Fatalf("workforce page=%#v error=%v", page, err)
	}
	closeDB()
}

func TestIdentityDirectoryQueryCompositionAndStableOrdering(t *testing.T) {
	store, closeDB := scriptedSQLIdentity(&identitySQLState{})
	defer closeDB()
	query := identitymodel.IdentityListQuery{
		Search:       " User ",
		SearchFields: []string{"name", "email"},
		Filters:      map[string]any{"status": " Active ", "account_type": "Human"},
		Sort: []identitymodel.IdentitySortRule{
			{Field: "name", Direction: "desc"},
			{Field: "id", Direction: "asc"},
		},
	}
	columns := map[string]string{
		"id": "id", "name": "name", "email": "email",
		"status": "status", "account_type": "account_type",
	}
	conditions := identityDirectoryPredicates(query, columns)
	statement, args, err := store.identityDirectoryPageSQL(t.Context(), "workspace", "_identity_users", []string{"id"}, identitymodel.IdentityListQuery{PageSize: 20, Sort: query.Sort}, conditions)
	if err != nil || !strings.Contains(statement, `"workspace_id" = ?`) || !strings.Contains(statement, `ORDER BY "name" DESC, "id" ASC LIMIT ?`) {
		t.Fatalf("statement=%q args=%#v err=%v", statement, args, err)
	}
	if keys := sortedStringKeys(map[string]any{"z": true, "a": true, "m": true}); !reflect.DeepEqual(keys, []string{"a", "m", "z"}) {
		t.Fatalf("keys=%#v", keys)
	}
}
