package identity_test

import (
	"path/filepath"
	"slices"
	"testing"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestStandalonePermissionReconcileIsIdempotentAndSurvivesRestart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "identity-permissions.db")
	registry, err := identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	open := func() (*database.IdentityStore, *identitypersistence.SQLIdentityStore, *identityapplication.IdentityPermissionCatalogApplicationService) {
		store, openErr := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: databasePath})
		if openErr != nil {
			t.Fatal(openErr)
		}
		if schemaErr := store.EnsureSchema(t.Context()); schemaErr != nil {
			_ = store.Close()
			t.Fatal(schemaErr)
		}
		repository, repositoryErr := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
		if repositoryErr != nil {
			_ = store.Close()
			t.Fatal(repositoryErr)
		}
		service, serviceErr := identityapplication.NewIdentityPermissionCatalogApplicationService(repository, registry, "workspace-primary")
		if serviceErr != nil {
			_ = store.Close()
			t.Fatal(serviceErr)
		}
		return store, repository, service
	}
	wantCount := len(registry.OwnedPermissionDefinitions(identityapplication.IdentityBuiltinAuthorizationOwner))

	store, repository, service := open()
	first, err := service.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner)
	if err != nil || first.Inserted != wantCount || first.DefinitionCount != wantCount {
		t.Fatalf("first reconcile=%+v err=%v", first, err)
	}
	if !service.PermissionIsExecutable(identityapplication.IdentityActionRolesList) || service.PermissionIsExecutable("identity.unknown") {
		t.Fatal("first reconcile did not publish a fail-closed executable permission snapshot")
	}
	second, err := service.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner)
	if err != nil || second.Unchanged != wantCount || second.Inserted != 0 || second.Updated != 0 || second.Retired != 0 || second.PreviousSnapshotHash != first.SnapshotHash {
		t.Fatalf("second reconcile=%+v err=%v", second, err)
	}
	rows, err := repository.ListIdentityPermissionDefinitions(t.Context(), "workspace-primary")
	if err != nil || len(rows) != wantCount {
		t.Fatalf("permission rows=%+v err=%v", rows, err)
	}
	if changed, err := repository.SetIdentityPermissionDefinitionEnabled(t.Context(), "workspace-primary", identityapplication.IdentityActionRolesList, false); err != nil || !changed {
		t.Fatalf("disable Identity permission changed=%t err=%v", changed, err)
	}
	if changed, err := repository.SetIdentityPermissionDefinitionEnabled(t.Context(), "workspace-primary", identityapplication.IdentityActionRolesList, false); err != nil || changed {
		t.Fatalf("idempotent disable changed=%t err=%v", changed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restartedStore, restartedRepository, restartedService := open()
	defer restartedStore.Close()
	restarted, err := restartedService.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner)
	if err != nil || restarted.Unchanged != wantCount {
		t.Fatalf("restart reconcile=%+v err=%v", restarted, err)
	}
	if restartedService.PermissionIsExecutable(identityapplication.IdentityActionRolesList) || !restartedService.PermissionIsExecutable(identityapplication.IdentityActionPermissionsList) {
		t.Fatal("restart runtime snapshot did not preserve disabled and enabled permission states")
	}
	restartedRows, err := restartedRepository.ListIdentityPermissionDefinitions(t.Context(), "workspace-primary")
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range restartedRows {
		if definition.PermissionKey == identityapplication.IdentityActionRolesList && definition.Enabled {
			t.Fatal("reconcile reset the persisted administrator enablement decision")
		}
		if definition.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive {
			t.Fatalf("permission %q status=%q", definition.PermissionKey, definition.DefinitionStatus)
		}
	}
}

func TestPermissionReconcileRetiresRestoresAndRejectsConflictingSnapshots(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "identity-permission-reconcile.db")
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	definition := func(workspaceID, owner, key, snapshot, hash string) identitymodel.IdentityPermissionDefinitionRecord {
		return identitymodel.IdentityPermissionDefinitionRecord{
			WorkspaceID: workspaceID, PermissionKey: key, ResourceKey: "roles", ActionKey: "read",
			Label: key, Category: "Identity", SourceKind: "builtin_surface", SourceOwner: owner,
			DefinitionHash: hash, SourceSnapshotHash: snapshot,
		}
	}
	reconcile := func(workspaceID, owner, previous, snapshot string, definitions ...identitymodel.IdentityPermissionDefinitionRecord) (identitymodel.IdentityPermissionReconcileReceipt, error) {
		return repository.ReconcileIdentityPermissionDefinitions(t.Context(), identitymodel.IdentityPermissionReconcileRequest{
			WorkspaceID: workspaceID, SourceOwner: owner, PreviousSnapshotHash: previous,
			SnapshotHash: snapshot, Definitions: definitions,
		})
	}

	const workspaceID = "workspace-primary"
	const owner = "identity:builtin"
	if receipt, err := reconcile(workspaceID, owner, "", "snapshot-1",
		definition(workspaceID, owner, "permission.one", "snapshot-1", "hash-one"),
		definition(workspaceID, owner, "permission.two", "snapshot-1", "hash-two"),
	); err != nil || receipt.Inserted != 2 {
		t.Fatalf("initial receipt=%+v err=%v", receipt, err)
	}
	if changed, err := repository.SetIdentityPermissionDefinitionEnabled(t.Context(), workspaceID, "permission.two", false); err != nil || !changed {
		t.Fatalf("disable permission.two changed=%t err=%v", changed, err)
	}
	if receipt, err := reconcile(workspaceID, owner, "snapshot-1", "snapshot-2",
		definition(workspaceID, owner, "permission.one", "snapshot-2", "hash-one"),
	); err != nil || receipt.Retired != 1 {
		t.Fatalf("retirement receipt=%+v err=%v", receipt, err)
	}
	if changed, err := repository.SetIdentityPermissionDefinitionEnabled(t.Context(), workspaceID, "permission.two", true); err != nil || changed {
		t.Fatalf("retired permission enablement changed=%t err=%v", changed, err)
	}
	if receipt, err := reconcile(workspaceID, owner, "snapshot-2", "snapshot-3",
		definition(workspaceID, owner, "permission.one", "snapshot-3", "hash-one"),
		definition(workspaceID, owner, "permission.two", "snapshot-3", "hash-two-restored"),
	); err != nil || receipt.Updated != 2 {
		t.Fatalf("restoration receipt=%+v err=%v", receipt, err)
	}
	rows, err := repository.ListIdentityPermissionDefinitions(t.Context(), workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive {
			t.Fatalf("permission %q status=%q", row.PermissionKey, row.DefinitionStatus)
		}
		if row.PermissionKey == "permission.two" && row.Enabled {
			t.Fatal("retire and restore reset the administrator disabled state")
		}
	}
	if _, err := reconcile(workspaceID, owner, "stale-snapshot", "snapshot-4",
		definition(workspaceID, owner, "permission.one", "snapshot-4", "hash-one"),
	); err == nil {
		t.Fatal("stale reconcile was accepted")
	}
	if _, err := reconcile(workspaceID, "module:conflict", "", "module-snapshot",
		definition(workspaceID, "module:conflict", "a.new", "module-snapshot", "hash-new"),
		definition(workspaceID, "module:conflict", "permission.one", "module-snapshot", "hash-conflict"),
	); err == nil {
		t.Fatal("canonical owner conflict was accepted")
	}
	rows, err = repository.ListIdentityPermissionDefinitions(t.Context(), workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, row.PermissionKey)
	}
	if slices.Contains(keys, "a.new") {
		t.Fatalf("owner conflict did not roll back the transaction: %v", keys)
	}
	const secondWorkspace = "workspace-secondary"
	if receipt, err := reconcile(secondWorkspace, "module:conflict", "", "secondary-snapshot",
		definition(secondWorkspace, "module:conflict", "permission.one", "secondary-snapshot", "secondary-hash"),
	); err != nil || receipt.Inserted != 1 {
		t.Fatalf("workspace-isolated receipt=%+v err=%v", receipt, err)
	}
}

func TestPermissionReconcileParticipatesInHostTransaction(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "identity-permission-host-transaction.db")
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	request := identitymodel.IdentityPermissionReconcileRequest{
		WorkspaceID: "workspace-primary", SourceOwner: "identity:builtin", SnapshotHash: "snapshot-1",
		Definitions: []identitymodel.IdentityPermissionDefinitionRecord{{
			WorkspaceID: "workspace-primary", PermissionKey: "identity.roles.get", ResourceKey: "identity.roles", ActionKey: "get",
			Label: "Get role", Category: "Identity", SourceKind: "builtin_surface", SourceOwner: "identity:builtin",
			DefinitionHash: "definition-1", SourceSnapshotHash: "snapshot-1",
		}},
	}

	rolledBack, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rolledBackContext := transaction.WithExecutor(t.Context(), rolledBack)
	if receipt, reconcileErr := repository.ReconcileIdentityPermissionDefinitions(rolledBackContext, request); reconcileErr != nil || receipt.Inserted != 1 {
		_ = rolledBack.Rollback()
		t.Fatalf("host transaction reconcile=%+v err=%v", receipt, reconcileErr)
	}
	inside, err := repository.ListIdentityPermissionDefinitions(rolledBackContext, "workspace-primary")
	if err != nil || len(inside) != 1 {
		_ = rolledBack.Rollback()
		t.Fatalf("host transaction rows=%+v err=%v", inside, err)
	}
	if err := rolledBack.Rollback(); err != nil {
		t.Fatal(err)
	}
	afterRollback, err := repository.ListIdentityPermissionDefinitions(t.Context(), "workspace-primary")
	if err != nil || len(afterRollback) != 0 {
		t.Fatalf("reconcile escaped host rollback: rows=%+v err=%v", afterRollback, err)
	}

	committed, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	committedContext := transaction.WithExecutor(t.Context(), committed)
	if receipt, reconcileErr := repository.ReconcileIdentityPermissionDefinitions(committedContext, request); reconcileErr != nil || receipt.Inserted != 1 {
		_ = committed.Rollback()
		t.Fatalf("committed host reconcile=%+v err=%v", receipt, reconcileErr)
	}
	if err := committed.Commit(); err != nil {
		t.Fatal(err)
	}
	afterCommit, err := repository.ListIdentityPermissionDefinitions(t.Context(), "workspace-primary")
	if err != nil || len(afterCommit) != 1 || afterCommit[0].PermissionKey != "identity.roles.get" {
		t.Fatalf("host commit rows=%+v err=%v", afterCommit, err)
	}
	definition, found, err := repository.GetIdentityPermissionDefinition(t.Context(), "workspace-primary", "identity.roles.get")
	if err != nil || !found || !definition.Enabled {
		t.Fatalf("get committed permission=%+v found=%t err=%v", definition, found, err)
	}
	if _, found, err := repository.GetIdentityPermissionDefinition(t.Context(), "workspace-secondary", "identity.roles.get"); err != nil || found {
		t.Fatalf("cross-workspace permission found=%t err=%v", found, err)
	}
	if changed, err := repository.SetIdentityPermissionDefinitionEnabled(t.Context(), "workspace-primary", "missing", false); err != nil || changed {
		t.Fatalf("missing permission enablement changed=%t err=%v", changed, err)
	}

	enablementTx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	enablementContext := transaction.WithExecutor(t.Context(), enablementTx)
	if changed, setErr := repository.SetIdentityPermissionDefinitionEnabled(enablementContext, "workspace-primary", "identity.roles.get", false); setErr != nil || !changed {
		_ = enablementTx.Rollback()
		t.Fatalf("host enablement changed=%t err=%v", changed, setErr)
	}
	insideDefinition, found, err := repository.GetIdentityPermissionDefinition(enablementContext, "workspace-primary", "identity.roles.get")
	if err != nil || !found || insideDefinition.Enabled {
		_ = enablementTx.Rollback()
		t.Fatalf("host enablement read=%+v found=%t err=%v", insideDefinition, found, err)
	}
	if err := enablementTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	afterEnablementRollback, found, err := repository.GetIdentityPermissionDefinition(t.Context(), "workspace-primary", "identity.roles.get")
	if err != nil || !found || !afterEnablementRollback.Enabled {
		t.Fatalf("enablement escaped host rollback: permission=%+v found=%t err=%v", afterEnablementRollback, found, err)
	}
}

func TestActionCannotReuseAnotherActionPermission(t *testing.T) {
	var ownerAction identitymodel.IdentityActionDefinition
	for _, candidate := range identityapplication.StandaloneIdentityAuthorizationSliceActions() {
		if candidate.HTTP != nil && candidate.Permission != nil {
			ownerAction = candidate
			break
		}
	}
	if ownerAction.HTTP == nil {
		t.Fatal("no HTTP permission Action found")
	}
	consumerAction := actioncontract.CloneDefinition(ownerAction)
	consumerAction.Key = "module.consumer.roles.list"
	consumerAction.Owner = "module:consumer"
	consumerAction.HTTP.RouteTemplate = "/module/consumer/roles"
	consumerAction.HTTP.DisplayRouteTemplate = "/module/consumer/roles"
	if _, err := identityapplication.NewIdentityActionRegistry([]identitymodel.IdentityActionDefinition{ownerAction, consumerAction}); err == nil {
		t.Fatal("Action with a differently keyed Permission was accepted")
	}
}
