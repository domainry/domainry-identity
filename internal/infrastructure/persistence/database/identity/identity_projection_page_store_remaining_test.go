package identity

import (
	"database/sql/driver"
	"reflect"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityProjectionCountStep(total int64) identitySQLQueryStep {
	return identitySQLQueryStep{columns: []string{"count"}, rows: [][]driver.Value{{total}}}
}

func identityProjectionUserColumns() []string {
	return []string{
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status", "version", "created_at", "updated_at",
	}
}

func identityProjectionUserRow() []driver.Value {
	return []driver.Value{
		"user", "User", "", "", "", "", "", "", "",
		"user@example.test", "", "human", "en-US", "UTC", "store", "sales", nil, "/user", "E001", "employee", "active", "2026-01-01", nil, "active", int64(1), "created", "updated",
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
			querySteps: []identitySQLQueryStep{identityProjectionCountStep(1)},
		},
		{querySteps: []identitySQLQueryStep{
			identityProjectionCountStep(1),
			{columns: []string{"only"}, rows: [][]driver.Value{{"value"}}},
		}},
		{querySteps: []identitySQLQueryStep{
			identityProjectionCountStep(1),
			{columns: identityProjectionUserColumns(), nextErr: errProfileBindingSQL},
		}},
	} {
		store, closeDB = scriptedSQLIdentity(state)
		if _, err := store.SearchIdentityUsers(t.Context(), "workspace", query); err == nil {
			t.Fatal("user projection failure ignored")
		}
		closeDB()
	}

	store, closeDB = scriptedSQLIdentity(&identitySQLState{querySteps: []identitySQLQueryStep{
		identityProjectionCountStep(3),
		{columns: identityProjectionUserColumns(), rows: [][]driver.Value{identityProjectionUserRow()}},
	}})
	page, err := store.SearchIdentityUsers(t.Context(), "workspace", query)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "user" || page.HasNext || page.Total != 3 {
		t.Fatalf("user page=%#v error=%v", page, err)
	}
	closeDB()
}

func TestIdentityProjectionQueryCompositionAndStableOrdering(t *testing.T) {
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
	conditions := identityProjectionPredicates(query, columns)
	statement, args, err := store.identityProjectionPageSQL(t.Context(), "workspace", "_identity_users", []string{"id"}, identitymodel.IdentityListQuery{PageSize: 20, Sort: query.Sort}, conditions)
	if err != nil || !strings.Contains(statement, `"workspace_id" = ?`) || !strings.Contains(statement, `ORDER BY "name" DESC, "id" ASC LIMIT ?`) {
		t.Fatalf("statement=%q args=%#v err=%v", statement, args, err)
	}
	if keys := sortedStringKeys(map[string]any{"z": true, "a": true, "m": true}); !reflect.DeepEqual(keys, []string{"a", "m", "z"}) {
		t.Fatalf("keys=%#v", keys)
	}
}
