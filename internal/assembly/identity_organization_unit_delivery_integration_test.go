package assembly

import (
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-identity/internal/platform/config"
	organizationunit "github.com/domainry/domainry-identity/organizationunit"
)

func TestOrganizationUnitDeliveryCreatesRealDepartmentWithAtomicScopedReplay(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", filepath.Join(t.TempDir(), "identity-organization-unit-delivery.db")
	cfg.IdentityWorkspaceID, cfg.AuthAudience = "workspace-primary", "runtime-app"
	cfg.AuthJWTSecret, cfg.AuthDefaultPassword = "organization-unit-signing-secret", "AdminPassword1!"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	manifest, err := loadManifest(cfg.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.IdentityBootstrap == nil {
		manifest.IdentityBootstrap = &identitymodel.ManifestIdentityBootstrapSchema{}
	}
	manifest.IdentityBootstrap.OrganizationUnits = append(manifest.IdentityBootstrap.OrganizationUnits,
		identitymodel.ManifestIdentityOrganizationUnitSchema{ID: "company-a", Code: "COMPANY-A", Name: "Company A", NodeType: identitymodel.IdentityOrganizationUnitCompany, Status: "active"},
		identitymodel.ManifestIdentityOrganizationUnitSchema{ID: "company-b", Code: "COMPANY-B", Name: "Company B", NodeType: identitymodel.IdentityOrganizationUnitCompany, Status: "active"},
		identitymodel.ManifestIdentityOrganizationUnitSchema{ID: "company-disabled", Code: "COMPANY-DISABLED", Name: "Company Disabled", NodeType: identitymodel.IdentityOrganizationUnitCompany, Status: "disabled"},
	)
	manifest.Roles = append(manifest.Roles,
		identitymodel.RoleSchema{Key: "organization_unit_operator", Name: "Organization unit operator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
			identitycontract.IdentityOrganizationUnitDeliveryCreatePermission, identitycontract.IdentityOrganizationUnitDeliveryResolvePermission)},
		identitymodel.RoleSchema{Key: "scoped_organization_unit_operator", Name: "Scoped organization unit operator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOrgChild,
			identitycontract.IdentityOrganizationUnitDeliveryCreatePermission, identitycontract.IdentityOrganizationUnitDeliveryResolvePermission)},
		identitymodel.RoleSchema{Key: "organization_crud_only", Name: "Organization CRUD only", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
			"identity.organization_units.create", "identity.organization_units.update", "identity.organization_units.get", "identity.organization_units.list")},
	)
	manifest.Users = append(manifest.Users,
		identitymodel.ManifestIdentityUserSchema{ID: "organization_unit_operator_user", Name: "Organization unit operator", Email: "organization_unit_operator@example.com", Status: "active", RoleKeys: []string{"organization_unit_operator"}},
		identitymodel.ManifestIdentityUserSchema{ID: "scoped_organization_unit_operator_user", Name: "Scoped organization unit operator", Email: "scoped_organization_unit_operator@example.com", OrgID: "company-a", Status: "active", RoleKeys: []string{"scoped_organization_unit_operator"}},
		identitymodel.ManifestIdentityUserSchema{ID: "organization_crud_only_user", Name: "Organization CRUD only", Email: "organization_crud_only@example.com", Status: "active", RoleKeys: []string{"organization_crud_only"}},
	)

	open := func() (*Core, *database.IdentityStore) {
		store, err := database.OpenContext(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureSchema(t.Context()); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		core, err := NewWithManifest(t.Context(), cfg, store, manifest, Options{WorkspaceID: cfg.IdentityWorkspaceID})
		if err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		return core, store
	}
	core, store := open()
	application := identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: identitysdk.ApplicationKey(cfg.AuthAudience)}
	if _, err := core.Binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}
	login := func(email string) identitysdk.AuthSession {
		session, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
			WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: email, Password: cfg.AuthDefaultPassword,
		})
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	operator := login("organization_unit_operator@example.com")
	crudOnly := login("organization_crud_only@example.com")
	delivery := core.Binding.(organizationunit.Binding).OrganizationUnitDelivery()
	create := organizationunit.DeliveryRequest{
		ContractVersion: organizationunit.DeliveryContractVersionV1, AccessToken: operator.AccessToken, IdempotencyKey: "department-sales-create-1",
		Organization: organizationunit.CreateCandidate{
			OrganizationID: "department-sales", Code: "DEPARTMENT-SALES", Name: "Sales", NodeType: organizationunit.NodeTypeDepartment,
			ParentOrganizationID: "company-a", SortOrder: 10, ExpectedVersion: 0,
		},
	}
	created, err := delivery.CreateOrganizationUnit(t.Context(), create)
	if err != nil || created.Replayed || created.Organization.Version != 1 || created.Organization.NodeType != organizationunit.NodeTypeDepartment || created.Organization.Path != "/company-a/department-sales" || created.Organization.ParentOrganizationID != "company-a" {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	persisted, found, err := core.Identity.FindOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), "department-sales")
	if err != nil || !found || persisted.NodeType != identitymodel.IdentityOrganizationUnitDepartment || persisted.ParentID == nil || *persisted.ParentID != "company-a" {
		t.Fatalf("persisted department=%+v found=%v err=%v", persisted, found, err)
	}
	replayed, err := delivery.CreateOrganizationUnit(t.Context(), create)
	if err != nil || !replayed.Replayed || replayed.DeliveryID != created.DeliveryID {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	reused := create
	reused.Organization.Name = "Different"
	if _, err := delivery.CreateOrganizationUnit(t.Context(), reused); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("same key different payload error=%v", err)
	} else {
		var sdkErr *identitysdk.Error
		if !errors.As(err, &sdkErr) {
			t.Fatalf("adapter returned %T, want *identitysdk.Error", err)
		}
	}
	concurrentReplayRequest := create
	concurrentReplayRequest.IdempotencyKey = "department-concurrent-replay"
	concurrentReplayRequest.Organization = organizationunit.CreateCandidate{
		OrganizationID: "department-concurrent", Code: "DEPARTMENT-CONCURRENT", Name: "Concurrent", NodeType: organizationunit.NodeTypeDepartment,
		ParentOrganizationID: "company-a",
	}
	var concurrentResults [2]organizationunit.DeliveryResult
	var concurrentErrors [2]error
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range concurrentResults {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			concurrentResults[index], concurrentErrors[index] = delivery.CreateOrganizationUnit(t.Context(), concurrentReplayRequest)
		}(index)
	}
	close(start)
	wait.Wait()
	if concurrentErrors[0] != nil || concurrentErrors[1] != nil || concurrentResults[0].DeliveryID == "" || concurrentResults[0].DeliveryID != concurrentResults[1].DeliveryID || concurrentResults[0].Replayed == concurrentResults[1].Replayed {
		t.Fatalf("concurrent replay results=%+v errors=%v", concurrentResults, concurrentErrors)
	}

	concurrentSiblingRequests := [2]organizationunit.DeliveryRequest{create, create}
	concurrentSiblingRequests[0].IdempotencyKey = "department-sibling-a"
	concurrentSiblingRequests[0].Organization = organizationunit.CreateCandidate{OrganizationID: "department-sibling-a", Code: "DEPARTMENT-SIBLING-A", Name: "Concurrent sibling", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-a"}
	concurrentSiblingRequests[1].IdempotencyKey = "department-sibling-b"
	concurrentSiblingRequests[1].Organization = organizationunit.CreateCandidate{OrganizationID: "department-sibling-b", Code: "DEPARTMENT-SIBLING-B", Name: "concurrent SIBLING", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-a"}
	var siblingResults [2]organizationunit.DeliveryResult
	var siblingErrors [2]error
	start = make(chan struct{})
	for index := range concurrentSiblingRequests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			siblingResults[index], siblingErrors[index] = delivery.CreateOrganizationUnit(t.Context(), concurrentSiblingRequests[index])
		}(index)
	}
	close(start)
	wait.Wait()
	siblingSuccesses, siblingConflicts := 0, 0
	for index, err := range siblingErrors {
		if err == nil && siblingResults[index].Organization.ID != "" {
			siblingSuccesses++
			continue
		}
		if apperror.CodeOf(err) == "backend.identity.organization_unit_name_exists" {
			siblingConflicts++
		}
	}
	if siblingSuccesses != 1 || siblingConflicts != 1 {
		t.Fatalf("concurrent sibling results=%+v errors=%v", siblingResults, siblingErrors)
	}
	scoped := login("scoped_organization_unit_operator@example.com")
	resolved, err := delivery.ResolveOrganizationUnit(t.Context(), organizationunit.ResolveRequest{
		ContractVersion: organizationunit.DeliveryContractVersionV1, AccessToken: scoped.AccessToken,
		OrganizationID: "department-sales", NodeType: organizationunit.NodeTypeDepartment,
	})
	if err != nil || resolved.ParentOrganizationID != "company-a" || resolved.Path != created.Organization.Path {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	if _, err := delivery.ResolveOrganizationUnit(t.Context(), organizationunit.ResolveRequest{
		ContractVersion: organizationunit.DeliveryContractVersionV1, AccessToken: scoped.AccessToken,
		OrganizationID: "department-sales", NodeType: organizationunit.NodeTypeTeam,
	}); apperror.CodeOf(err) != "backend.identity.organization_unit_projection_denied" {
		t.Fatalf("wrong node type resolve error=%v", err)
	}

	scopedCreate := create
	scopedCreate.AccessToken, scopedCreate.IdempotencyKey = scoped.AccessToken, "department-support-create-1"
	scopedCreate.Organization = organizationunit.CreateCandidate{OrganizationID: "department-support", Code: "DEPARTMENT-SUPPORT", Name: "Support", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-a"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), scopedCreate); err != nil {
		t.Fatalf("scoped parent create: %v", err)
	}
	if _, err := delivery.ResolveOrganizationUnit(t.Context(), organizationunit.ResolveRequest{
		ContractVersion: organizationunit.DeliveryContractVersionV1, AccessToken: scoped.AccessToken,
		OrganizationID: "department-support", NodeType: organizationunit.NodeTypeDepartment,
	}); apperror.CodeOf(err) != "auth.authorization_stale" {
		t.Fatalf("stale authorization revision error=%v", err)
	}
	scoped = login("scoped_organization_unit_operator@example.com")
	outOfScope := scopedCreate
	outOfScope.AccessToken = scoped.AccessToken
	outOfScope.IdempotencyKey = "department-other-create-1"
	outOfScope.Organization = organizationunit.CreateCandidate{OrganizationID: "department-other", Code: "DEPARTMENT-OTHER", Name: "Other", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-b"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), outOfScope); apperror.CodeOf(err) != "backend.identity.organization_unit_scope_denied" {
		t.Fatalf("out-of-scope parent error=%v", err)
	}
	parentMutation, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parentMutation.ExecContext(t.Context(), `UPDATE _identity_organization_units SET status = ? WHERE workspace_id = ? AND id = ?`, "disabled", cfg.IdentityWorkspaceID, "company-b"); err != nil {
		_ = parentMutation.Rollback()
		t.Fatal(err)
	}
	parentReader, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		_ = parentMutation.Rollback()
		t.Fatal(err)
	}
	type lockedParentResult struct {
		parent identitymodel.IdentityOrganizationUnit
		found  bool
		err    error
	}
	parentResult := make(chan lockedParentResult, 1)
	go func() {
		parent, found, lockErr := core.IdentityStore.LockIdentityOrganizationUnitDeliveryParent(
			identitytransaction.WithExecutor(t.Context(), parentReader), cfg.IdentityWorkspaceID, "company-b",
		)
		parentResult <- lockedParentResult{parent: parent, found: found, err: lockErr}
	}()
	select {
	case result := <-parentResult:
		_ = parentReader.Rollback()
		_ = parentMutation.Rollback()
		t.Fatalf("parent lock did not wait for concurrent mutation: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	if err := parentMutation.Commit(); err != nil {
		_ = parentReader.Rollback()
		t.Fatal(err)
	}
	select {
	case result := <-parentResult:
		_ = parentReader.Rollback()
		if result.err != nil || !result.found || result.parent.Status != identitymodel.IdentityStatusDisabled {
			t.Fatalf("locked parent result=%+v", result)
		}
	case <-time.After(3 * time.Second):
		_ = parentReader.Rollback()
		t.Fatal("parent lock did not resume after concurrent mutation committed")
	}
	crudAttempt := create
	crudAttempt.AccessToken, crudAttempt.IdempotencyKey = crudOnly.AccessToken, "generic-crud-bypass"
	crudAttempt.Organization = organizationunit.CreateCandidate{OrganizationID: "department-crud-bypass", Code: "DEPARTMENT-CRUD-BYPASS", Name: "CRUD bypass", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-a"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), crudAttempt); apperror.CodeOf(err) != "backend.identity.organization_unit_scope_denied" {
		t.Fatalf("generic CRUD permission reached delivery: %v", err)
	}
	invalidRoot := create
	invalidRoot.IdempotencyKey = "company-child-invalid"
	invalidRoot.Organization = organizationunit.CreateCandidate{OrganizationID: "company-child", Code: "COMPANY-CHILD", Name: "Company child", NodeType: organizationunit.NodeTypeCompany, ParentOrganizationID: "company-a"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), invalidRoot); apperror.CodeOf(err) != "backend.identity.organization_unit_type_invalid" {
		t.Fatalf("company child error=%v", err)
	}
	invalidStore := create
	invalidStore.IdempotencyKey = "store-child-invalid"
	invalidStore.Organization = organizationunit.CreateCandidate{OrganizationID: "store-child", Code: "STORE-CHILD", Name: "Store child", NodeType: organizationunit.NodeTypeStore, ParentOrganizationID: "company-a"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), invalidStore); apperror.CodeOf(err) != "backend.identity.organization_unit_type_invalid" {
		t.Fatalf("store child error=%v", err)
	}
	duplicateID := create
	duplicateID.IdempotencyKey = "department-id-conflict"
	duplicateID.Organization = organizationunit.CreateCandidate{OrganizationID: "department-sales", Code: "DEPARTMENT-SALES-OTHER", Name: "Sales other", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-a"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), duplicateID); apperror.CodeOf(err) != "backend.identity.organization_unit_version_conflict" {
		t.Fatalf("existing ID version error=%v", err)
	}
	inactiveParent := create
	inactiveParent.IdempotencyKey = "inactive-parent"
	inactiveParent.Organization = organizationunit.CreateCandidate{OrganizationID: "department-inactive", Code: "DEPARTMENT-INACTIVE", Name: "Inactive", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-disabled"}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), inactiveParent); apperror.CodeOf(err) != "backend.identity.organization_unit_parent_invalid" {
		t.Fatalf("inactive parent error=%v", err)
	}
	duplicateCode := create
	duplicateCode.IdempotencyKey = "duplicate-code"
	duplicateCode.Organization.OrganizationID, duplicateCode.Organization.Name = "department-sales-copy", "Sales copy"
	if _, err := delivery.CreateOrganizationUnit(t.Context(), duplicateCode); apperror.CodeOf(err) != "backend.identity.organization_unit_code_exists" {
		t.Fatalf("duplicate code error=%v", err)
	}

	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := create
	rolledBack.IdempotencyKey = "department-rollback-create"
	rolledBack.Organization = organizationunit.CreateCandidate{OrganizationID: "department-rollback", Code: "DEPARTMENT-ROLLBACK", Name: "Rollback", NodeType: organizationunit.NodeTypeDepartment, ParentOrganizationID: "company-a"}
	if _, err := delivery.CreateOrganizationUnit(identitytransaction.WithExecutor(t.Context(), tx), rolledBack); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertOrganizationUnitDeliveryRowCounts(t, store.DB(), cfg.IdentityWorkspaceID, "department-rollback", rolledBack.IdempotencyKey, 0)

	if err := core.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, store = open()
	delivery = core.Binding.(organizationunit.Binding).OrganizationUnitDelivery()
	restartReplay, err := delivery.CreateOrganizationUnit(t.Context(), create)
	if err != nil || !restartReplay.Replayed || restartReplay.DeliveryID != created.DeliveryID {
		t.Fatalf("restart replay=%+v err=%v", restartReplay, err)
	}
	parentID := "company-a"
	if err := core.Identity.UpsertOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), identitymodel.IdentityOrganizationUnit{
		ID: "department-sales", Code: "DEPARTMENT-SALES", Name: "Externally changed", NodeType: identitymodel.IdentityOrganizationUnitDepartment,
		ParentID: &parentID, SortOrder: 10, Status: identitymodel.IdentityStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := delivery.CreateOrganizationUnit(t.Context(), create); apperror.CodeOf(err) != "backend.identity.organization_unit_external_change" {
		t.Fatalf("external change replay error=%v", err)
	}
	assertOrganizationUnitDeliveryRowCounts(t, store.DB(), cfg.IdentityWorkspaceID, "department-sales", create.IdempotencyKey, 1)
	if err := core.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func assertOrganizationUnitDeliveryRowCounts(t *testing.T, db *sql.DB, workspaceID, organizationID, idempotencyKey string, want int) {
	t.Helper()
	checks := []struct {
		table, column, value string
	}{
		{"_identity_organization_units", "id", organizationID},
		{"_identity_organization_unit_delivery_states", "organization_id", organizationID},
		{"_identity_organization_unit_deliveries", "idempotency_key", idempotencyKey},
		{"_audit_events", "record_id", organizationID},
	}
	for _, check := range checks {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+check.table+" WHERE workspace_id = ? AND "+check.column+" = ?", workspaceID, check.value).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s count=%d want=%d", check.table, count, want)
		}
	}
}
