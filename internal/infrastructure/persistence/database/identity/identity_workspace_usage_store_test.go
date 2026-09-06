package identity

import (
	"database/sql/driver"
	"strings"
	"testing"
)

func TestWorkspaceIdentityUsageStoreUsesOneAggregateQueryWithoutPII(t *testing.T) {
	state := &identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"workspace_id", "account_type", "status", "count"},
		rows: [][]driver.Value{
			{"workspace-a", "human", "active", int64(2)},
			{"workspace-b", "service", "disabled", int64(1)},
		},
	}}}
	store, closeDB := scriptedSQLIdentity(state)
	defer closeDB()
	groups, err := store.CountIdentityWorkspaceUsage(t.Context(), []string{"workspace-a", "workspace-b"})
	if err != nil || len(groups) != 2 || groups[0].Count != 2 || groups[1].Count != 1 {
		t.Fatalf("groups=%+v err=%v", groups, err)
	}
	if state.queryCount != 1 || len(state.queryStatements) != 1 {
		t.Fatalf("query count=%d statements=%v", state.queryCount, state.queryStatements)
	}
	statement := strings.ToLower(state.queryStatements[0])
	for _, required := range []string{"workspace_id", "account_type", "status", "count(*)", "group by", "order by", " in ("} {
		if !strings.Contains(statement, required) {
			t.Fatalf("aggregate query missing %q: %s", required, statement)
		}
	}
	for _, forbidden := range []string{"email", "phone", "name", "employee_profile", "select *", "tenant"} {
		if strings.Contains(statement, forbidden) {
			t.Fatalf("aggregate query contains %q: %s", forbidden, statement)
		}
	}
}

func TestWorkspaceIdentityActiveHumanRoleUsageUsesOneDistinctAggregateQuery(t *testing.T) {
	state := &identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"workspace_id", "count"},
		rows: [][]driver.Value{
			{"workspace-a", int64(2)},
			{"workspace-b", int64(1)},
		},
	}}}
	store, closeDB := scriptedSQLIdentity(state)
	defer closeDB()
	counts, err := store.CountIdentityWorkspaceActiveHumanAccountsWithActiveRole(t.Context(), []string{"workspace-a", "workspace-b"})
	if err != nil || len(counts) != 2 || counts[0].Count != 2 || counts[1].Count != 1 {
		t.Fatalf("counts=%+v err=%v", counts, err)
	}
	if state.queryCount != 1 || len(state.queryStatements) != 1 {
		t.Fatalf("query count=%d statements=%v", state.queryCount, state.queryStatements)
	}
	statement := strings.ToLower(state.queryStatements[0])
	for _, required := range []string{"select distinct", "inner join", "_identity_user_role_assignments", "account_type", "status", "count(*)", "group by", " in ("} {
		if !strings.Contains(statement, required) {
			t.Fatalf("active human role aggregate query missing %q: %s", required, statement)
		}
	}
	for _, forbidden := range []string{"email", "phone", "name", "employee_profile", "select *", "tenant"} {
		if strings.Contains(statement, forbidden) {
			t.Fatalf("active human role aggregate query contains %q: %s", forbidden, statement)
		}
	}
}
