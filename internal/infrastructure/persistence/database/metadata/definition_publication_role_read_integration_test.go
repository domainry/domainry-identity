package metadata

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestApplyRoleDefinitionsRemainListableAfterRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	open := func() (*database.IdentityStore, MetadataStore) {
		store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		return store, NewMetadataStore(store)
	}
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test role definition publication")
	store, repository := open()
	mutations := make([]metadatamodel.MetadataDefinitionMutation, 0, 4)
	for _, key := range []string{"member", "coach", "store_manager", "finance"} {
		payload, err := json.Marshal(identitymodel.RoleSchema{Key: key, Name: key, RecordScope: "all_records", DataPermissions: []identitymodel.DataPermission{{ObjectKey: "booking", Scope: "all_records", Read: true}}})
		if err != nil {
			t.Fatal(err)
		}
		mutations = append(mutations, metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: key, Request: metadatamodel.MetadataDefinitionUpsertRequest{SourceKind: "admin", SourceID: "gym-roles", Payload: payload}})
	}
	publication := &metadatamodel.MetadataDefinitionPublication{WorkspaceID: identitymodel.InstallationWorkspaceID}
	if _, err := repository.ApplyDefinitionMutations(t.Context(), scope, mutations, nil, publication); err != nil {
		t.Fatal(err)
	}
	definitions, err := repository.ListDefinitions(t.Context(), scope, "role")
	if err != nil || len(definitions) != 4 {
		t.Fatalf("list applied roles count=%d err=%v", len(definitions), err)
	}
	if definitions[0].SchemaVersion != "1" {
		t.Fatalf("first applied schema version=%q", definitions[0].SchemaVersion)
	}
	if err := store.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	reopened, restartedRepository := open()
	t.Cleanup(func() { _ = reopened.CloseContext(t.Context()) })
	definitions, err = restartedRepository.ListDefinitions(t.Context(), scope, "role")
	if err != nil || len(definitions) != 4 {
		t.Fatalf("list restarted roles count=%d err=%v", len(definitions), err)
	}
}

func TestDirectRolePublicationRollbackAndDisableAreAtomicWithDirectoryAndAudit(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseContext(t.Context()) })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository := NewMetadataStore(store)
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test direct role publication")
	publication := &metadatamodel.MetadataDefinitionPublication{WorkspaceID: identitymodel.InstallationWorkspaceID}
	audit := func(id, event string) auditmodel.AuditEvent {
		return auditmodel.AuditEvent{ID: id, WorkspaceID: identitymodel.InstallationWorkspaceID, Event: event, ObjectKey: "role", RecordID: "reviewer", ActorID: "admin", RoleKey: "admin", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	payload := func(name string) json.RawMessage {
		raw, marshalErr := json.Marshal(identitymodel.RoleSchema{Key: "reviewer", Name: name, RecordScope: "all_records"})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return raw
	}
	first, err := repository.PublishDefinition(t.Context(), scope, "role", "reviewer", metadatamodel.MetadataDefinitionUpsertRequest{Payload: payload("Reviewer")}, audit("audit-role-v1", "metadata_definition.saved"), publication)
	if err != nil {
		t.Fatal(err)
	}
	expected := first.SchemaHash
	second, err := repository.PublishDefinition(t.Context(), scope, "role", "reviewer", metadatamodel.MetadataDefinitionUpsertRequest{Payload: payload("Senior Reviewer"), ExpectedSchemaHash: &expected}, audit("audit-role-v2", "metadata_definition.saved"), publication)
	if err != nil {
		t.Fatal(err)
	}
	assertRoleDirectoryState(t, store, "Senior Reviewer", "active", 2)
	rolledBack, err := repository.RollbackDefinition(t.Context(), scope, "role", "reviewer", metadatamodel.MetadataDefinitionRollbackRequest{TargetVersion: "1", ExpectedSchemaHash: second.SchemaHash, BusinessReason: "restore"}, audit("audit-role-rollback", "metadata_definition.rolled_back"), publication)
	if err != nil {
		t.Fatal(err)
	}
	assertRoleDirectoryState(t, store, "Reviewer", "active", 3)
	if err := repository.DisableDefinition(t.Context(), scope, "role", "reviewer", strings.Repeat("0", 64), audit("audit-role-stale-disable", "metadata_definition.disabled"), publication); err == nil {
		t.Fatal("stale role disable was accepted")
	}
	assertRoleDirectoryState(t, store, "Reviewer", "active", 3)
	if err := repository.DisableDefinition(t.Context(), scope, "role", "reviewer", rolledBack.SchemaHash, audit("audit-role-disable", "metadata_definition.disabled"), publication); err != nil {
		t.Fatal(err)
	}
	assertRoleDirectoryState(t, store, "Reviewer", "disabled", 4)
	var disabled int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _metadata_role_definitions WHERE resource_key='reviewer' AND disabled_at IS NOT NULL`).Scan(&disabled); err != nil || disabled != 1 {
		t.Fatalf("disabled role definitions=%d err=%v", disabled, err)
	}
}

func assertRoleDirectoryState(t *testing.T, store *database.IdentityStore, wantLabel, wantStatus string, wantAuditCount int) {
	t.Helper()
	var label, status string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT label, status FROM _identity_roles WHERE workspace_id=? AND role_key='reviewer'`, identitymodel.InstallationWorkspaceID).Scan(&label, &status); err != nil {
		t.Fatal(err)
	}
	if label != wantLabel || status != wantStatus {
		t.Fatalf("role directory label=%q status=%q want label=%q status=%q", label, status, wantLabel, wantStatus)
	}
	var audits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id=? AND object_key='role' AND record_id='reviewer'`, identitymodel.InstallationWorkspaceID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != wantAuditCount {
		t.Fatalf("role audit count=%d want=%d", audits, wantAuditCount)
	}
}
