package identity_test

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormsqlite "github.com/domainry/domainry-orm/sqlite"
)

func TestStoreOrganizationPageIsStableScopedAndBoundedInOneRepositoryQuery(t *testing.T) {
	databaseStore, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "store-organization-page.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer databaseStore.Close()
	if err := databaseStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	store.BindOperationsPersistence()
	companyA, companyB, division := "company-a", "company-b", "division-a"
	units := []identitymodel.IdentityOrganizationUnit{
		{ID: companyA, Code: "COMPANY-A", Name: "Company A", NodeType: identitymodel.IdentityOrganizationUnitCompany, Path: "/company-a", Status: identitymodel.IdentityStatusActive},
		{ID: companyB, Code: "COMPANY-B", Name: "Company B", NodeType: identitymodel.IdentityOrganizationUnitCompany, Path: "/company-b", Status: identitymodel.IdentityStatusActive},
		{ID: division, Code: "DIVISION-A", Name: "Division A", NodeType: identitymodel.IdentityOrganizationUnitDepartment, ParentID: &companyA, Path: "/company-a/division-a", AncestorIDs: []string{companyA}, Depth: 1, Status: identitymodel.IdentityStatusActive},
		{ID: "store-a-01", Code: "STORE-A-01", Name: "Store A 01", NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &companyA, Path: "/company-a/store-a-01", AncestorIDs: []string{companyA}, Depth: 1, Status: identitymodel.IdentityStatusActive},
		{ID: "store-a-02", Code: "STORE-A-02", Name: "Store A 02", NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &companyA, Path: "/company-a/store-a-02", AncestorIDs: []string{companyA}, Depth: 1, Status: identitymodel.IdentityStatusDisabled},
		{ID: "store-b-01", Code: "STORE-B-01", Name: "Store B 01", NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &companyB, Path: "/company-b/store-b-01", AncestorIDs: []string{companyB}, Depth: 1, Status: identitymodel.IdentityStatusActive},
		// This deliberately malformed legacy row proves the page query performs
		// the company-parent integrity check without a per-item parent lookup.
		{ID: "store-orphan", Code: "STORE-ORPHAN", Name: "Store Orphan", NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &division, Path: "/company-a/division-a/store-orphan", AncestorIDs: []string{companyA, division}, Depth: 2, Status: identitymodel.IdentityStatusActive},
	}
	for _, unit := range units {
		if err := store.UpsertIdentityOrganizationUnit(t.Context(), "workspace-primary", unit); err != nil {
			t.Fatalf("upsert %s: %v", unit.ID, err)
		}
	}

	all := identitymodel.IdentityDataScopeFilter{Unrestricted: true}
	firstFetch, err := store.ListIdentityStoreOrganizationsPage(t.Context(), "workspace-primary", all, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreOrganizationIDs(t, firstFetch, "store-a-01", "store-a-02", "store-b-01")
	if firstFetch[1].Status != string(identitymodel.IdentityStatusDisabled) || firstFetch[1].Version != 1 {
		t.Fatalf("status/version projection=%+v", firstFetch[1])
	}
	next, err := store.ListIdentityStoreOrganizationsPage(t.Context(), "workspace-primary", all, "store-a-02", 3)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreOrganizationIDs(t, next, "store-b-01")

	scoped := identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"store-a-02", "store-a-01"}}
	scopePage, err := store.ListIdentityStoreOrganizationsPage(t.Context(), "workspace-primary", scoped, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreOrganizationIDs(t, scopePage, "store-a-01", "store-a-02")

	// A cursor is only a lower bound. Reapplying the permission scope in the
	// same query prevents it from exposing later out-of-scope store IDs.
	bypassAttempt, err := store.ListIdentityStoreOrganizationsPage(t.Context(), "workspace-primary", identitymodel.IdentityDataScopeFilter{OwnerOrgIDs: []string{"store-a-01"}}, "store-a-01", 3)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreOrganizationIDs(t, bypassAttempt)

	empty, err := store.ListIdentityStoreOrganizationsPage(t.Context(), "workspace-primary", all, "zzzz", 3)
	if err != nil {
		t.Fatal(err)
	}
	assertStoreOrganizationIDs(t, empty)
}

func TestStoreOrganizationCreateKeepsRuntimeOpaqueIDAndReplaysInsideSQLiteImmediateUoW(t *testing.T) {
	databaseStore, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "store-organization-immediate.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer databaseStore.Close()
	if err := databaseStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	store.BindOperationsPersistence()
	if err := store.UpsertIdentityOrganizationUnit(t.Context(), "workspace-primary", identitymodel.IdentityOrganizationUnit{
		ID: "company", Code: "COMPANY", Name: "Company", NodeType: identitymodel.IdentityOrganizationUnitCompany,
		Path: "/company", Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	hostTransaction, err := ormsqlite.NewProfile().BeginWrite(t.Context(), databaseStore.DB())
	if err != nil {
		t.Fatal(err)
	}
	const opaqueID = "01J9Q8X7K6M5N4P3R2T1V0WXYZ"
	parentID := "company"
	mutation := identitymodel.IdentityStoreOrganizationDeliveryMutation{
		WorkspaceID: "workspace-primary", ActorID: "runtime-actor", IdempotencyKey: "runtime-store-create-1", RequestFingerprint: "runtime-store-fingerprint-1",
		Operation: identitymodel.IdentityStoreOrganizationCreate, ExpectedVersion: 0, DataScope: identitymodel.IdentityDataScopeFilter{Unrestricted: true},
		Organization: identitymodel.IdentityOrganizationUnit{
			ID: opaqueID, Code: "STORE-OPAQUE", Name: "Opaque Store", NodeType: identitymodel.IdentityOrganizationUnitStore,
			ParentID: &parentID, Path: "/company/" + opaqueID, AncestorIDs: []string{"company"}, Depth: 1, Status: identitymodel.IdentityStatusActive,
		},
	}
	transactionContext := identitytransaction.WithExecutor(t.Context(), hostTransaction)
	created, err := store.ExecuteIdentityStoreOrganizationDelivery(transactionContext, mutation)
	if err != nil {
		_ = hostTransaction.Rollback(t.Context())
		t.Fatal(err)
	}
	if created.Result.Organization.ID != opaqueID || created.Result.Replayed {
		_ = hostTransaction.Rollback(t.Context())
		t.Fatalf("created receipt=%+v", created)
	}
	replayed, err := store.ExecuteIdentityStoreOrganizationDelivery(transactionContext, mutation)
	if err != nil {
		_ = hostTransaction.Rollback(t.Context())
		t.Fatal(err)
	}
	if !replayed.Result.Replayed || replayed.Result.DeliveryID != created.Result.DeliveryID || replayed.Result.Organization.ID != opaqueID {
		_ = hostTransaction.Rollback(t.Context())
		t.Fatalf("replayed receipt=%+v", replayed)
	}
	if err := hostTransaction.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for table, target := range map[string][2]string{
		"_identity_organization_units": {"id", opaqueID},
		"_operations":                  {"idempotency_key", mutation.IdempotencyKey},
	} {
		var count int
		if err := databaseStore.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE workspace_id = ? AND "+target[0]+" = ?", "workspace-primary", target[1]).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback left %s count=%d err=%v", table, count, err)
		}
	}
}

func assertStoreOrganizationIDs(t *testing.T, items []identitymodel.IdentityStoreOrganization, want ...string) {
	t.Helper()
	if len(items) != len(want) {
		t.Fatalf("store count=%d want=%d items=%+v", len(items), len(want), items)
	}
	for index := range want {
		if items[index].ID != want[index] {
			t.Fatalf("store[%d]=%q want=%q items=%+v", index, items[index].ID, want[index], items)
		}
	}
}
