package identity

import (
	"database/sql"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestMemoryIdentityUserRoleLifecycleEdges(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	if _, err := store.ListIdentityUsers(ctx, ""); err == nil {
		t.Fatal("invalid workspace accepted")
	}
	if err := store.UpsertIdentityUser(ctx, "default", identitymodel.IdentityUser{}); err == nil {
		t.Fatal("empty user accepted")
	}
	if err := store.UpsertIdentityUser(ctx, "default", identitymodel.IdentityUser{ID: "b", Phone: "123"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUser(ctx, "other", identitymodel.IdentityUser{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUsersAtomically(ctx, "default", []identitymodel.IdentityUser{{ID: "a"}, {ID: "c", Status: identitymodel.IdentityStatusDisabled}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityUsersAtomically(ctx, "default", []identitymodel.IdentityUser{{}}); err == nil {
		t.Fatal("atomic empty user accepted")
	}
	users, err := store.ListIdentityUsers(ctx, "default")
	if err != nil || len(users) != 3 || users[0].ID != "a" {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	loaded, found, err := store.GetIdentityUser(ctx, "default", "b")
	if err != nil || !found || loaded.Phone != "123" {
		t.Fatalf("loaded=%#v found=%v err=%v", loaded, found, err)
	}
	if _, _, err := store.GetIdentityUser(ctx, "", "b"); err == nil {
		t.Fatal("invalid get accepted")
	}
	if err := store.SetIdentityUserStatus(ctx, "default", "missing", identitymodel.IdentityStatusDisabled); err == nil {
		t.Fatal("missing status succeeded")
	}
	if err := store.SetIdentityUserStatus(ctx, "default", "b", identitymodel.IdentityStatusDisabled); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityUser(ctx, "default", "missing"); err == nil {
		t.Fatal("missing remove succeeded")
	}
	store.credentials["default\x00b"] = identitymodel.IdentityCredential{UserID: "b"}
	store.externalAccounts["default\x00account"] = identitymodel.IdentityExternalAccount{ID: "account", UserID: "b"}
	store.externalAccounts["default\x00account-other"] = identitymodel.IdentityExternalAccount{ID: "account-other", UserID: "other"}
	store.externalAccounts["other\x00account"] = identitymodel.IdentityExternalAccount{ID: "account", UserID: "b"}
	store.refreshTokens["default\x00token"] = identitymodel.AuthRefreshToken{ID: "token", UserID: "b"}
	store.refreshTokens["default\x00token-other"] = identitymodel.AuthRefreshToken{ID: "token-other", UserID: "other"}
	store.refreshTokens["other\x00token"] = identitymodel.AuthRefreshToken{ID: "token", UserID: "b"}
	store.userRoles["default\x00b\x00role"] = identitymodel.IdentityUserRoleAssignment{UserID: "b", RoleID: "role"}
	store.userRoles["default\x00other\x00role"] = identitymodel.IdentityUserRoleAssignment{UserID: "other", RoleID: "role"}
	store.userRoles["other\x00b\x00role"] = identitymodel.IdentityUserRoleAssignment{UserID: "b", RoleID: "role"}
	if err := store.RemoveIdentityUser(ctx, "default", "b"); err != nil {
		t.Fatal(err)
	}
	delete(store.userRoles, "default\x00other\x00role")

	if err := store.UpsertIdentityRole(ctx, "default", identitymodel.IdentityRole{}); err == nil {
		t.Fatal("empty role accepted")
	}
	if err := store.UpsertIdentityRole(ctx, "default", identitymodel.IdentityRole{ID: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityRole(ctx, "default", identitymodel.IdentityRole{ID: "a", Status: identitymodel.IdentityStatusDisabled}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertIdentityRole(ctx, "other", identitymodel.IdentityRole{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	roles, err := store.ListIdentityRoles(ctx, "default")
	if err != nil || len(roles) != 2 || roles[0].ID != "a" {
		t.Fatalf("roles=%#v err=%v", roles, err)
	}
	for _, assignment := range []identitymodel.IdentityUserRoleAssignment{{}, {UserID: "u"}} {
		if err := store.AssignIdentityUserRole(ctx, "default", assignment); err == nil {
			t.Fatalf("invalid assignment accepted: %#v", assignment)
		}
	}
	if err := store.AssignIdentityUserRole(ctx, "default", identitymodel.IdentityUserRoleAssignment{UserID: "u2", RoleID: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignIdentityUserRole(ctx, "default", identitymodel.IdentityUserRoleAssignment{UserID: "u3", RoleID: "other-role"}); err != nil {
		t.Fatal(err)
	}
	expires := "2026-08-01T00:00:00Z"
	if err := store.AssignIdentityUserRole(ctx, "default", identitymodel.IdentityUserRoleAssignment{
		UserID: "u5", RoleID: "other-role", ValidUntil: expires, ExpiresAt: &expires,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignIdentityUserRole(ctx, "other", identitymodel.IdentityUserRoleAssignment{UserID: "u4", RoleID: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignIdentityUserRole(ctx, "default", identitymodel.IdentityUserRoleAssignment{UserID: "u1", RoleID: "a"}); err != nil {
		t.Fatal(err)
	}
	assignments, err := store.ListIdentityUserRoleAssignments(ctx, "default", "")
	if err != nil || len(assignments) != 4 || assignments[0].UserID != "u1" {
		t.Fatalf("assignments=%#v err=%v", assignments, err)
	}
	if err := store.RemoveIdentityUserRole(ctx, "default", "u1", "a"); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityRole(ctx, "default", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryIdentityRoleRequestDecisionEdges(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	request := identitymodel.IdentityRoleRequest{ID: "request", UserID: "user", RoleIDs: []string{"role"}, Status: "pending"}
	if _, err := store.CreateIdentityRoleRequest(ctx, "default", request); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyIdentityRoleRequestDecision(ctx, "", request, nil, "pending"); err == nil {
		t.Fatal("invalid workspace accepted")
	}
	for _, assignment := range []identitymodel.IdentityUserRoleAssignment{
		{RoleID: "role"},
		{UserID: "user"},
	} {
		if err := store.ApplyIdentityRoleRequestDecision(ctx, "default", request, []identitymodel.IdentityUserRoleAssignment{assignment}, "pending"); err == nil {
			t.Fatalf("invalid assignment accepted: %+v", assignment)
		}
	}
	if err := store.ApplyIdentityRoleRequestDecision(ctx, "default", identitymodel.IdentityRoleRequest{ID: "missing"}, nil, "pending"); apperror.CodeOf(err) != "backend.identity.role_request_concurrent_decision" {
		t.Fatalf("missing request error=%v", err)
	}
	if err := store.ApplyIdentityRoleRequestDecision(ctx, "default", request, nil, "approved"); apperror.CodeOf(err) != "backend.identity.role_request_concurrent_decision" {
		t.Fatalf("stale request error=%v", err)
	}
	request.Status = "approved"
	assignments := []identitymodel.IdentityUserRoleAssignment{
		{UserID: "user", RoleID: "role"},
		{UserID: "user", RoleID: "explicit", Source: "import", Status: "suspended"},
	}
	if err := store.ApplyIdentityRoleRequestDecision(ctx, "default", request, assignments, "pending"); err != nil {
		t.Fatal(err)
	}
	stored, err := store.ListIdentityUserRoleAssignments(ctx, "default", "user")
	if err != nil || len(stored) != 2 || stored[0].Source != "import" && stored[1].Source != "import" {
		t.Fatalf("assignments=%+v error=%v", stored, err)
	}
	for _, assignment := range stored {
		if assignment.RoleID == "role" && (assignment.Source != "governance_request" || assignment.Status != "active") {
			t.Fatalf("default assignment=%+v", assignment)
		}
	}
}

func TestMemoryIdentityEntitlementBatchEdges(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	valid := identitymodel.IdentityEntitlementBatchMutation{
		WorkspaceID: "default", ActorID: "admin", IdempotencyKey: "batch",
		RequestFingerprint: "fingerprint",
		Items:              []identitymodel.IdentityEntitlementBatchItem{{Operation: "grant", UserID: "user", RoleID: "role"}},
		Assignments:        []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role"}},
	}
	invalid := []identitymodel.IdentityEntitlementBatchMutation{
		{WorkspaceID: ""},
		{WorkspaceID: "default"},
		{WorkspaceID: "default", ActorID: "admin"},
		{WorkspaceID: "default", ActorID: "admin", IdempotencyKey: "batch"},
		{WorkspaceID: "default", ActorID: "admin", IdempotencyKey: "batch", RequestFingerprint: "fingerprint"},
		{
			WorkspaceID: "default", ActorID: "admin", IdempotencyKey: "batch", RequestFingerprint: "fingerprint",
			Items: []identitymodel.IdentityEntitlementBatchItem{{}},
		},
	}
	for index, mutation := range invalid {
		if _, err := store.ApplyIdentityEntitlementBatch(ctx, mutation); err == nil {
			t.Fatalf("invalid mutation %d accepted: %+v", index, mutation)
		}
	}
	invalidAssignment := valid
	invalidAssignment.Assignments = []identitymodel.IdentityUserRoleAssignment{{RoleID: "role"}}
	if _, err := store.ApplyIdentityEntitlementBatch(ctx, invalidAssignment); err == nil {
		t.Fatal("invalid batch assignment accepted")
	}
	invalidAssignment.Assignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user"}}
	if _, err := store.ApplyIdentityEntitlementBatch(ctx, invalidAssignment); err == nil {
		t.Fatal("batch assignment without role accepted")
	}
	if err := store.AssignIdentityUserRole(ctx, "default", identitymodel.IdentityUserRoleAssignment{UserID: "existing", RoleID: "existing"}); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ApplyIdentityEntitlementBatch(ctx, valid)
	if err != nil || receipt.Replayed || receipt.ID == "" {
		t.Fatalf("receipt=%+v error=%v", receipt, err)
	}
	loaded, found, err := store.GetIdentityEntitlementBatchReceipt(ctx, "default", " batch ")
	if err != nil || !found || loaded.ID != receipt.ID {
		t.Fatalf("loaded=%+v found=%v error=%v", loaded, found, err)
	}
	if _, _, err := store.GetIdentityEntitlementBatchReceipt(ctx, "", "batch"); err == nil {
		t.Fatal("invalid receipt workspace accepted")
	}
	replayed, err := store.ApplyIdentityEntitlementBatch(ctx, valid)
	if err != nil || !replayed.Replayed {
		t.Fatalf("replayed=%+v error=%v", replayed, err)
	}
	conflict := valid
	conflict.RequestFingerprint = "different"
	if _, err := store.ApplyIdentityEntitlementBatch(ctx, conflict); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("conflict error=%v", err)
	}
}

func TestMemoryIdentityRequestsMenusAndPolicyEdges(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	for _, request := range []identitymodel.IdentityRoleRequest{{}, {ID: "id"}, {ID: "id", UserID: "user"}} {
		if _, err := store.CreateIdentityRoleRequest(ctx, "default", request); err == nil {
			t.Fatalf("invalid request accepted: %#v", request)
		}
	}
	request, err := store.CreateIdentityRoleRequest(ctx, "default", identitymodel.IdentityRoleRequest{ID: "b", UserID: "user", RoleIDs: []string{"r2", "r1", "r1"}, CreatedAt: "1"})
	if err != nil || request.Status != "pending" || len(request.RoleIDs) != 2 {
		t.Fatalf("request=%#v err=%v", request, err)
	}
	if _, err := store.CreateIdentityRoleRequest(ctx, "default", identitymodel.IdentityRoleRequest{ID: "a", UserID: "other", RoleIDs: []string{"r"}, Status: "approved", CreatedAt: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateIdentityRoleRequest(ctx, "default", identitymodel.IdentityRoleRequest{ID: "c", UserID: "different", RoleIDs: []string{"r"}, Status: "approved", CreatedAt: "2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateIdentityRoleRequest(ctx, "other", identitymodel.IdentityRoleRequest{ID: "other", UserID: "user", RoleIDs: []string{"r"}}); err != nil {
		t.Fatal(err)
	}
	requests, err := store.ListIdentityRoleRequests(ctx, "default", "", "")
	if err != nil || len(requests) != 3 || requests[0].ID != "c" {
		t.Fatalf("requests=%#v err=%v", requests, err)
	}
	if filtered, err := store.ListIdentityRoleRequests(ctx, "default", "approved", "other"); err != nil || len(filtered) != 1 {
		t.Fatalf("filtered=%#v err=%v", filtered, err)
	}
	if err := store.UpdateIdentityRoleRequest(ctx, "default", identitymodel.IdentityRoleRequest{}); err == nil {
		t.Fatal("empty update accepted")
	}
	if err := store.UpdateIdentityRoleRequest(ctx, "default", identitymodel.IdentityRoleRequest{ID: "missing"}); err == nil {
		t.Fatal("missing update accepted")
	}
	request.Status = "approved"
	if err := store.UpdateIdentityRoleRequest(ctx, "default", request); err != nil {
		t.Fatal(err)
	}

	if err := store.UpsertIdentityMenu(ctx, "default", identitymodel.IdentityMenu{}); err == nil {
		t.Fatal("empty menu accepted")
	}
	for _, menu := range []identitymodel.IdentityMenu{{ID: "b", SortOrder: 1}, {ID: "a", Key: "key-a", SortOrder: 1, Status: identitymodel.IdentityStatusDisabled}, {ID: "c", SortOrder: 0}} {
		if err := store.UpsertIdentityMenu(ctx, "default", menu); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.UpsertIdentityMenu(ctx, "other", identitymodel.IdentityMenu{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	menus, err := store.ListIdentityMenus(ctx, "default")
	if err != nil || len(menus) != 3 || menus[0].ID != "c" || menus[1].ID != "b" {
		t.Fatalf("menus=%#v err=%v", menus, err)
	}
	if err := store.SetIdentityRoleMenus(ctx, "default", "role", []string{"a", "b", "key-a", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIdentityRoleMenus(ctx, "default", "other-role", []string{"c"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIdentityRoleMenus(ctx, "other", "foreign-role", []string{"other"}); err != nil {
		t.Fatal(err)
	}
	if specific, err := store.ListIdentityRoleMenuAssignments(ctx, "default", "role"); err != nil || len(specific) != 3 {
		t.Fatalf("specific=%#v err=%v", specific, err)
	}
	if all, err := store.ListIdentityRoleMenuAssignments(ctx, "default", ""); err != nil || len(all) != 4 {
		t.Fatalf("all=%#v err=%v", all, err)
	}
	if err := store.RemoveIdentityMenu(ctx, "default", "missing"); err == nil {
		t.Fatal("missing menu removed")
	}
	if err := store.RemoveIdentityMenu(ctx, "default", "a"); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIdentityMenusAtomically(ctx, "default", []identitymodel.IdentityMenu{{ID: "missing"}}); err == nil {
		t.Fatal("missing atomic menu removed")
	}
	if err := store.RemoveIdentityMenusAtomically(ctx, "default", []identitymodel.IdentityMenu{{ID: "b", Key: "b"}, {ID: "c", Key: "c"}}); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityValueAndDepartmentEdges(t *testing.T) {
	if identityID("a.b", "c:d", "e/f") != "a_b_c_d_e_f" || len(uniqueSortedStrings([]string{"", "a"})) != 1 {
		t.Fatal("identity value helpers")
	}
	empty := " "
	value := "x"
	if nullableString(nil) != nil || nullableString(&empty) != nil || nullableString(&value) != "x" || nullableText(" ") != nil || nullableText("x") != "x" {
		t.Fatal("nullable helpers")
	}
	if pointerFromNull(sql.NullString{}) != nil || *pointerFromNull(sql.NullString{String: "x", Valid: true}) != "x" || valueFromNull(sql.NullString{}) != "" || valueFromNull(sql.NullString{String: "x", Valid: true}) != "x" {
		t.Fatal("null helpers")
	}
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	if err := store.UpsertIdentityDepartment(ctx, "default", identitymodel.IdentityDepartment{}); err == nil {
		t.Fatal("empty department accepted")
	}
	parentA, parentB := "a", "b"
	for _, department := range []identitymodel.IdentityDepartment{{ID: "root"}, {ID: "a2", ParentID: &parentA, Depth: 1, SortOrder: 2}, {ID: "a1", ParentID: &parentA, Depth: 1, SortOrder: 1}, {ID: "b1", ParentID: &parentB, Depth: 1}} {
		if err := store.UpsertIdentityDepartment(ctx, "default", department); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.UpsertIdentityDepartment(ctx, "other", identitymodel.IdentityDepartment{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	departments, err := store.ListIdentityDepartments(ctx, "default")
	if err != nil || len(departments) != 4 || identityDepartmentParentID(nil) != "" || identityDepartmentParentID(&parentA) != "a" {
		t.Fatalf("departments=%#v err=%v", departments, err)
	}
}
