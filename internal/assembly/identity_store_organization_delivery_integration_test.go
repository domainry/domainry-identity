package assembly

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestStoreOrganizationDeliveryIsAtomicScopedIdempotentAndRestartSafe(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	databasePath := filepath.Join(t.TempDir(), "identity-store-organization-delivery.db")
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", databasePath
	cfg.IdentityWorkspaceID, cfg.AuthAudience = "workspace-primary", "runtime-app"
	cfg.AuthJWTSecret, cfg.AuthDefaultPassword = "store-organization-signing-secret", "AdminPassword1!"
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
	)
	allStorePermissions := []string{
		identitycontract.IdentityStoreOrganizationDeliveryCreatePermission,
		identitycontract.IdentityStoreOrganizationDeliveryRenamePermission,
		identitycontract.IdentityStoreOrganizationDeliveryDisablePermission,
		identitycontract.IdentityStoreOrganizationDeliveryResolvePermission,
		identitycontract.IdentityStoreOrganizationDeliveryListPermission,
	}
	manifest.Roles = append(manifest.Roles,
		identitymodel.RoleSchema{Key: "store_operator", Name: "Store operator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, allStorePermissions...)},
		identitymodel.RoleSchema{Key: "org_store_creator", Name: "Organization store creator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOrg, identitycontract.IdentityStoreOrganizationDeliveryCreatePermission)},
		identitymodel.RoleSchema{Key: "target_store_creator", Name: "Target organization store creator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeTargetOrg, identitycontract.IdentityStoreOrganizationDeliveryCreatePermission)},
		identitymodel.RoleSchema{Key: "scoped_store_operator", Name: "Scoped store operator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeOrgChild,
			identitycontract.IdentityStoreOrganizationDeliveryCreatePermission,
			identitycontract.IdentityStoreOrganizationDeliveryListPermission,
		)},
		identitymodel.RoleSchema{Key: "organization_crud_operator", Name: "Organization CRUD operator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
			"identity.organization_units.create", "identity.organization_units.update", "identity.organization_units.get", "identity.organization_units.list")},
	)
	manifest.Users = append(manifest.Users, identitymodel.ManifestIdentityUserSchema{
		ID: "scoped_store_operator_user", Name: "Scoped store operator", Email: "scoped_store_operator@example.com",
		OrgID: "company-a", Status: "active", RoleKeys: []string{"scoped_store_operator"},
	}, identitymodel.ManifestIdentityUserSchema{
		ID: "org_store_creator_user", Name: "Organization store creator", Email: "org_store_creator@example.com",
		OrgID: "company-a", Status: "active", RoleKeys: []string{"org_store_creator"},
	}, identitymodel.ManifestIdentityUserSchema{
		ID: "target_store_creator_user", Name: "Target organization store creator", Email: "target_store_creator@example.com",
		OrgID: "company-b", SupportOrgID: "company-a", Status: "active", RoleKeys: []string{"target_store_creator"},
	})

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
	operatorSession := login("store_operator@example.com")
	delivery := core.Binding.(identitysdk.StoreOrganizationDeliveryBinding).StoreOrganizationDelivery()
	create := identitysdk.StoreOrganizationDeliveryRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1, AccessToken: operatorSession.AccessToken, IdempotencyKey: "store-create-1",
		Organization: identitysdk.StoreOrganizationMutation{
			Operation: identitysdk.StoreOrganizationCreate, OrganizationID: "store-1", Code: "STORE-1", Name: "Store One", ParentOrganizationID: "company-a",
		},
	}
	created, err := delivery.DeliverStoreOrganization(t.Context(), create)
	if err != nil || created.Replayed || created.Organization.Version != 1 || created.Organization.Path != "/company-a/store-1" || created.Organization.ParentOrganizationID != "company-a" {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	persisted, found, err := core.Identity.FindOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), "store-1")
	if err != nil || !found || persisted.NodeType != identitymodel.IdentityOrganizationUnitStore {
		t.Fatalf("persisted store=%+v found=%v err=%v", persisted, found, err)
	}
	replayed, err := delivery.DeliverStoreOrganization(t.Context(), create)
	if err != nil || !replayed.Replayed || replayed.DeliveryID != created.DeliveryID {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	reused := create
	reused.Organization.Name = "Different"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), reused); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("same key different payload error=%v", err)
	}
	var createAudits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND event = ? AND object_key = ? AND record_id = ?`, cfg.IdentityWorkspaceID, "identity.store_organization_delivery.create", "identity_organization_unit", "store-1").Scan(&createAudits); err != nil || createAudits != 1 {
		t.Fatalf("create audit count=%d err=%v", createAudits, err)
	}

	orgCreateSession := login("org_store_creator@example.com")
	orgCreate := create
	orgCreate.AccessToken, orgCreate.IdempotencyKey = orgCreateSession.AccessToken, "org-scope-create"
	orgCreate.Organization.OrganizationID, orgCreate.Organization.Code, orgCreate.Organization.Name = "org-scope-store", "ORG-SCOPE", "Org Scope Store"
	orgCreated, err := delivery.DeliverStoreOrganization(t.Context(), orgCreate)
	if err != nil || orgCreated.Organization.ParentOrganizationID != "company-a" {
		t.Fatalf("org-scope create=%+v err=%v", orgCreated, err)
	}
	orgCreateSession = login("org_store_creator@example.com")
	orgCreate.AccessToken = orgCreateSession.AccessToken
	beforeOrgReplay := loadStoreOrganizationReplaySnapshot(t, store, cfg.IdentityWorkspaceID, orgCreate.Organization.OrganizationID, orgCreate.IdempotencyKey)
	orgReplayed, err := delivery.DeliverStoreOrganization(t.Context(), orgCreate)
	if err != nil || !orgReplayed.Replayed || orgReplayed.DeliveryID != orgCreated.DeliveryID {
		t.Fatalf("org-scope replay=%+v err=%v", orgReplayed, err)
	}
	afterOrgReplay := loadStoreOrganizationReplaySnapshot(t, store, cfg.IdentityWorkspaceID, orgCreate.Organization.OrganizationID, orgCreate.IdempotencyKey)
	if afterOrgReplay != beforeOrgReplay {
		t.Fatalf("org-scope replay wrote state: before=%+v after=%+v", beforeOrgReplay, afterOrgReplay)
	}

	targetCreateSession := login("target_store_creator@example.com")
	targetCreate := create
	targetCreate.AccessToken, targetCreate.IdempotencyKey = targetCreateSession.AccessToken, "target-scope-create"
	targetCreate.Organization.OrganizationID, targetCreate.Organization.Code, targetCreate.Organization.Name = "target-scope-store", "TARGET-SCOPE", "Target Scope Store"
	targetCreated, err := delivery.DeliverStoreOrganization(t.Context(), targetCreate)
	if err != nil || targetCreated.Organization.ParentOrganizationID != "company-a" {
		t.Fatalf("target-scope create=%+v err=%v", targetCreated, err)
	}
	targetCreateSession = login("target_store_creator@example.com")
	targetCreate.AccessToken = targetCreateSession.AccessToken
	targetReplayed, err := delivery.DeliverStoreOrganization(t.Context(), targetCreate)
	if err != nil || !targetReplayed.Replayed || targetReplayed.DeliveryID != targetCreated.DeliveryID {
		t.Fatalf("target-scope replay=%+v err=%v", targetReplayed, err)
	}

	definitions := core.Identity.PublishedRoleDefinitions(t.Context())
	revoked := false
	for index := range definitions {
		if definitions[index].Key == "org_store_creator" {
			definitions[index].Permissions = nil
			revoked = true
		}
	}
	if !revoked {
		t.Fatal("org_store_creator definition not found")
	}
	core.Identity.ReplaceRoleDefinitions(definitions)
	orgCreate.AccessToken = login("org_store_creator@example.com").AccessToken
	beforeRevokedReplay := loadStoreOrganizationReplaySnapshot(t, store, cfg.IdentityWorkspaceID, orgCreate.Organization.OrganizationID, orgCreate.IdempotencyKey)
	if _, err := delivery.DeliverStoreOrganization(t.Context(), orgCreate); apperror.CodeOf(err) != "backend.identity.store_organization_scope_denied" {
		t.Fatalf("revoked create permission replay error=%v", err)
	}
	if after := loadStoreOrganizationReplaySnapshot(t, store, cfg.IdentityWorkspaceID, orgCreate.Organization.OrganizationID, orgCreate.IdempotencyKey); after != beforeRevokedReplay {
		t.Fatalf("revoked replay wrote state: before=%+v after=%+v", beforeRevokedReplay, after)
	}

	externallyMoved, found, err := core.Identity.FindOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), targetCreate.Organization.OrganizationID)
	if err != nil || !found {
		t.Fatalf("target store before external move found=%v err=%v", found, err)
	}
	companyB := "company-b"
	externallyMoved.ParentID = &companyB
	if err := core.Identity.UpsertOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), externallyMoved); err != nil {
		t.Fatal(err)
	}
	targetCreate.AccessToken = login("target_store_creator@example.com").AccessToken
	beforeExternalReplay := loadStoreOrganizationReplaySnapshot(t, store, cfg.IdentityWorkspaceID, targetCreate.Organization.OrganizationID, targetCreate.IdempotencyKey)
	if _, err := delivery.DeliverStoreOrganization(t.Context(), targetCreate); apperror.CodeOf(err) != "backend.identity.store_organization_external_change" {
		t.Fatalf("externally moved parent replay error=%v", err)
	}
	if after := loadStoreOrganizationReplaySnapshot(t, store, cfg.IdentityWorkspaceID, targetCreate.Organization.OrganizationID, targetCreate.IdempotencyKey); after != beforeExternalReplay {
		t.Fatalf("externally changed replay wrote state: before=%+v after=%+v", beforeExternalReplay, after)
	}

	resolved, err := delivery.ResolveStoreOrganization(t.Context(), identitysdk.StoreOrganizationResolveRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1, AccessToken: operatorSession.AccessToken, OrganizationID: "store-1",
	})
	if err != nil || resolved.ID != "store-1" || resolved.Version != 1 || len(resolved.AncestorIDs) != 1 || resolved.AncestorIDs[0] != "company-a" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	stores, err := delivery.ListStoreOrganizations(t.Context(), identitysdk.StoreOrganizationListRequest{ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1, AccessToken: operatorSession.AccessToken})
	if err != nil || !storeOrganizationListContains(stores.Items, "store-1") {
		t.Fatalf("stores=%+v err=%v", stores, err)
	}

	purposePrincipal, err := core.Identity.ResolvePrincipal(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), "store_operator_user")
	if err != nil {
		t.Fatal(err)
	}
	parentA := "company-a"
	if err := core.Identity.UpsertOrganizationUnitWithinDataScope(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), identitymodel.IdentityOrganizationUnit{
		ID: "generic-bypass", Code: "GENERIC-BYPASS", Name: "Generic bypass", NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &parentA, Status: identitymodel.IdentityStatusActive,
	}, purposePrincipal, "identity.organization_units.create"); apperror.CodeOf(err) != "auth.permission_denied" {
		t.Fatalf("purpose grant reached generic organization CRUD: %v", err)
	}
	crudSession := login("organization_crud_operator@example.com")
	crudAttempt := create
	crudAttempt.AccessToken, crudAttempt.IdempotencyKey = crudSession.AccessToken, "crud-store-attempt"
	crudAttempt.Organization.OrganizationID, crudAttempt.Organization.Code = "crud-store", "CRUD-STORE"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), crudAttempt); apperror.CodeOf(err) != "backend.identity.store_organization_scope_denied" {
		t.Fatalf("generic organization CRUD reached StoreOrganizationDelivery: %v", err)
	}

	scopedSession := login("scoped_store_operator@example.com")
	outOfHierarchy := create
	outOfHierarchy.AccessToken, outOfHierarchy.IdempotencyKey = scopedSession.AccessToken, "out-of-hierarchy"
	outOfHierarchy.Organization.OrganizationID, outOfHierarchy.Organization.Code, outOfHierarchy.Organization.ParentOrganizationID = "store-b", "STORE-B", "company-b"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), outOfHierarchy); apperror.CodeOf(err) != "backend.identity.store_organization_scope_denied" {
		t.Fatalf("out-of-hierarchy create error=%v", err)
	}
	inHierarchy := create
	inHierarchy.AccessToken, inHierarchy.IdempotencyKey = scopedSession.AccessToken, "in-hierarchy"
	inHierarchy.Organization.OrganizationID, inHierarchy.Organization.Code, inHierarchy.Organization.Name = "scoped-store", "SCOPED-STORE", "Scoped Store"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), inHierarchy); err != nil {
		t.Fatalf("in-hierarchy create error=%v", err)
	}
	companyBStore := create
	companyBStore.IdempotencyKey = "company-b-store"
	companyBStore.Organization.OrganizationID, companyBStore.Organization.Code, companyBStore.Organization.Name, companyBStore.Organization.ParentOrganizationID = "store-b", "STORE-B", "Store B", "company-b"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), companyBStore); err != nil {
		t.Fatalf("company-b store create error=%v", err)
	}

	// Re-login so the principal carries the current hierarchy revision after
	// store creation. Paging remains stable, bounded, and scoped on every call.
	scopedSession = login("scoped_store_operator@example.com")
	seenScoped := map[string]struct{}{}
	previousID, cursor := "", ""
	for {
		page, err := delivery.ListStoreOrganizations(t.Context(), identitysdk.StoreOrganizationListRequest{
			ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1,
			AccessToken:     scopedSession.AccessToken,
			PageSize:        1,
			Cursor:          cursor,
		})
		if err != nil {
			t.Fatalf("scoped page cursor=%q: %v", cursor, err)
		}
		if len(page.Items) > 1 {
			t.Fatalf("page exceeded bound: %+v", page)
		}
		for _, item := range page.Items {
			if previousID != "" && item.ID <= previousID {
				t.Fatalf("unstable store order previous=%q current=%q", previousID, item.ID)
			}
			if item.ID == "store-b" {
				t.Fatalf("scope leaked company-b store: %+v", page)
			}
			if _, duplicate := seenScoped[item.ID]; duplicate {
				t.Fatalf("duplicate store across pages: %q", item.ID)
			}
			seenScoped[item.ID], previousID = struct{}{}, item.ID
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == cursor {
			t.Fatalf("cursor did not advance: %q", cursor)
		}
		cursor = page.NextCursor
	}
	if _, ok := seenScoped["store-1"]; !ok {
		t.Fatalf("scoped pages omitted store-1: %+v", seenScoped)
	}
	if _, ok := seenScoped["scoped-store"]; !ok {
		t.Fatalf("scoped pages omitted scoped-store: %+v", seenScoped)
	}

	allFirst, err := delivery.ListStoreOrganizations(t.Context(), identitysdk.StoreOrganizationListRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1,
		AccessToken:     operatorSession.AccessToken,
		PageSize:        1,
	})
	if err != nil || allFirst.NextCursor == "" {
		t.Fatalf("all-scope first page=%+v err=%v", allFirst, err)
	}
	scopedWithAllCursor, err := delivery.ListStoreOrganizations(t.Context(), identitysdk.StoreOrganizationListRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1,
		AccessToken:     scopedSession.AccessToken,
		PageSize:        identitysdk.StoreOrganizationMaxPageSize,
		Cursor:          allFirst.NextCursor,
	})
	if err != nil {
		t.Fatalf("reuse all-scope cursor under scoped grant: %v", err)
	}
	if storeOrganizationListContains(scopedWithAllCursor.Items, "store-b") {
		t.Fatalf("cursor bypassed scoped grant: %+v", scopedWithAllCursor)
	}
	if _, err := delivery.ListStoreOrganizations(t.Context(), identitysdk.StoreOrganizationListRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1,
		AccessToken:     operatorSession.AccessToken,
		Cursor:          "not-a-valid-cursor",
	}); apperror.CodeOf(err) != "backend.identity.store_organization_cursor_invalid" {
		t.Fatalf("invalid cursor error=%v", err)
	}
	invalidParent := create
	invalidParent.IdempotencyKey = "invalid-parent"
	invalidParent.Organization.OrganizationID, invalidParent.Organization.Code, invalidParent.Organization.ParentOrganizationID = "nested-store", "NESTED-STORE", "store-1"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), invalidParent); apperror.CodeOf(err) != "backend.identity.store_organization_parent_invalid" {
		t.Fatalf("store parent accepted: %v", err)
	}

	staleRename := identitysdk.StoreOrganizationDeliveryRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1, AccessToken: operatorSession.AccessToken, IdempotencyKey: "store-rename-stale",
		Organization: identitysdk.StoreOrganizationMutation{Operation: identitysdk.StoreOrganizationRename, OrganizationID: "store-1", Name: "Stale", ExpectedVersion: 99},
	}
	if _, err := delivery.DeliverStoreOrganization(t.Context(), staleRename); apperror.CodeOf(err) != "backend.identity.store_organization_version_conflict" {
		t.Fatalf("stale rename error=%v", err)
	}
	rename := staleRename
	rename.IdempotencyKey, rename.Organization.Name, rename.Organization.ExpectedVersion = "store-rename-1", "Store One Renamed", 1
	renamed, err := delivery.DeliverStoreOrganization(t.Context(), rename)
	if err != nil || renamed.Organization.Version != 2 || renamed.Organization.Name != "Store One Renamed" || renamed.Organization.Code != "STORE-1" || renamed.Organization.ParentOrganizationID != "company-a" {
		t.Fatalf("renamed=%+v err=%v", renamed, err)
	}

	external := create
	external.IdempotencyKey = "external-store-create"
	external.Organization.OrganizationID, external.Organization.Code, external.Organization.Name = "external-store", "EXTERNAL", "External Store"
	if _, err := delivery.DeliverStoreOrganization(t.Context(), external); err != nil {
		t.Fatal(err)
	}
	externalUnit, found, err := core.Identity.FindOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), "external-store")
	if err != nil || !found {
		t.Fatalf("external store found=%v err=%v", found, err)
	}
	externalUnit.Name = "Out of band rename"
	if err := core.Identity.UpsertOrganizationUnit(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), externalUnit); err != nil {
		t.Fatal(err)
	}
	externalRename := rename
	externalRename.IdempotencyKey, externalRename.Organization.OrganizationID, externalRename.Organization.Name, externalRename.Organization.ExpectedVersion = "external-store-rename", "external-store", "Delivery rename", 1
	if _, err := delivery.DeliverStoreOrganization(t.Context(), externalRename); apperror.CodeOf(err) != "backend.identity.store_organization_external_change" {
		t.Fatalf("out-of-band change was overwritten: %v", err)
	}

	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := create
	rolledBack.IdempotencyKey = "store-rollback"
	rolledBack.Organization.OrganizationID, rolledBack.Organization.Code, rolledBack.Organization.Name = "store-rollback", "STORE-ROLLBACK", "Rollback Store"
	if _, err := delivery.DeliverStoreOrganization(identitytransaction.WithExecutor(t.Context(), tx), rolledBack); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for table, column := range map[string]string{
		"_identity_organization_units": "id", "_identity_store_organization_states": "organization_id",
		"_identity_store_organization_deliveries": "idempotency_key", "_audit_events": "record_id",
	} {
		value := "store-rollback"
		if table == "_identity_store_organization_deliveries" {
			value = rolledBack.IdempotencyKey
		}
		var count int
		if err := store.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE workspace_id = ? AND "+column+" = ?", cfg.IdentityWorkspaceID, value).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback left %s count=%d err=%v", table, count, err)
		}
	}

	disable := identitysdk.StoreOrganizationDeliveryRequest{
		ContractVersion: identitysdk.StoreOrganizationDeliveryContractVersionV1, AccessToken: operatorSession.AccessToken, IdempotencyKey: "store-disable-1",
		Organization: identitysdk.StoreOrganizationMutation{Operation: identitysdk.StoreOrganizationDisable, OrganizationID: "store-1", ExpectedVersion: renamed.Organization.Version},
	}
	disabled, err := delivery.DeliverStoreOrganization(t.Context(), disable)
	if err != nil || disabled.Organization.Status != "disabled" || disabled.Organization.Version != 3 {
		t.Fatalf("disabled=%+v err=%v", disabled, err)
	}

	if err := core.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, _ = open()
	defer core.CloseContext(t.Context())
	delivery = core.Binding.(identitysdk.StoreOrganizationDeliveryBinding).StoreOrganizationDelivery()
	restartReplay, err := delivery.DeliverStoreOrganization(t.Context(), create)
	if err != nil || !restartReplay.Replayed || restartReplay.DeliveryID != created.DeliveryID {
		t.Fatalf("restart replay=%+v err=%v", restartReplay, err)
	}
}

func storeOrganizationListContains(stores []identitysdk.StoreOrganization, id string) bool {
	for _, store := range stores {
		if store.ID == id {
			return true
		}
	}
	return false
}

type storeOrganizationReplaySnapshot struct {
	OrganizationUpdatedAt string
	StateUpdatedAt        string
	StateVersion          int64
	StateFingerprint      string
	DeliveryCount         int
	AuditCount            int
}

func loadStoreOrganizationReplaySnapshot(t *testing.T, store *database.IdentityStore, workspaceID, organizationID, idempotencyKey string) storeOrganizationReplaySnapshot {
	t.Helper()
	var snapshot storeOrganizationReplaySnapshot
	if err := store.DB().QueryRowContext(t.Context(), `SELECT updated_at FROM _identity_organization_units WHERE workspace_id = ? AND id = ?`, workspaceID, organizationID).Scan(&snapshot.OrganizationUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(t.Context(), `SELECT version, state_fingerprint, updated_at FROM _identity_store_organization_states WHERE workspace_id = ? AND organization_id = ?`, workspaceID, organizationID).Scan(&snapshot.StateVersion, &snapshot.StateFingerprint, &snapshot.StateUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_store_organization_deliveries WHERE workspace_id = ? AND idempotency_key = ?`, workspaceID, idempotencyKey).Scan(&snapshot.DeliveryCount); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND event = ? AND record_id = ?`, workspaceID, "identity.store_organization_delivery.create", organizationID).Scan(&snapshot.AuditCount); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
