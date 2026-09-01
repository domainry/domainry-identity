package identity_test

import (
	"path/filepath"
	"slices"
	"testing"

	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
	"github.com/domainry/domainry-orm/query"
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

	store, repository, service := open()
	first, err := service.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner)
	if err != nil || first.Inserted != 4 {
		t.Fatalf("first reconcile=%+v err=%v", first, err)
	}
	if !service.PermissionIsExecutable("identity.roles.read") || service.PermissionIsExecutable("identity.unknown") {
		t.Fatal("first reconcile did not publish a fail-closed executable permission snapshot")
	}
	second, err := service.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner)
	if err != nil || second.Unchanged != 4 || second.Inserted != 0 || second.Updated != 0 || second.Retired != 0 {
		t.Fatalf("second reconcile=%+v err=%v", second, err)
	}
	rows, err := repository.ListIdentityPermissionDefinitions(t.Context(), "workspace-primary")
	if err != nil || len(rows) != 4 {
		t.Fatalf("permission rows=%+v err=%v", rows, err)
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(repository.SQLRenderer(), "_identity_permissions", "workspace-primary").
		Set("enabled", false).
		Where(query.Equal("permission_key", "identity.roles.read")).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restartedStore, restartedRepository, restartedService := open()
	defer restartedStore.Close()
	restarted, err := restartedService.ReconcileOwner(t.Context(), identityapplication.IdentityBuiltinAuthorizationOwner)
	if err != nil || restarted.Unchanged != 4 {
		t.Fatalf("restart reconcile=%+v err=%v", restarted, err)
	}
	if restartedService.PermissionIsExecutable("identity.roles.read") || !restartedService.PermissionIsExecutable("identity.permissions.read") {
		t.Fatal("restart runtime snapshot did not preserve disabled and enabled permission states")
	}
	restartedRows, err := restartedRepository.ListIdentityPermissionDefinitions(t.Context(), "workspace-primary")
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range restartedRows {
		if definition.PermissionKey == "identity.roles.read" && definition.Enabled {
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
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(repository.SQLRenderer(), "_identity_permissions", workspaceID).
		Set("enabled", false).
		Where(query.Equal("permission_key", "permission.two")).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if receipt, err := reconcile(workspaceID, owner, "snapshot-1", "snapshot-2",
		definition(workspaceID, owner, "permission.one", "snapshot-2", "hash-one"),
	); err != nil || receipt.Retired != 1 {
		t.Fatalf("retirement receipt=%+v err=%v", receipt, err)
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
