package metadata

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"
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
		return store, NewMetadataStore(store, "workspace-primary")
	}
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test role definition publication")
	store, repository := open()
	mutations := make([]metadatamodel.MetadataDefinitionMutation, 0, 4)
	for _, key := range []string{"member", "coach", "store_manager", "finance"} {
		payload, err := json.Marshal(identitymodel.RoleSchema{Key: key, Name: key, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "booking.read")})
		if err != nil {
			t.Fatal(err)
		}
		mutations = append(mutations, metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: key, Request: metadatamodel.MetadataDefinitionUpsertRequest{SourceKind: "admin", SourceID: "gym-roles", Payload: payload}})
	}
	publication := &metadatamodel.MetadataDefinitionPublication{WorkspaceID: "workspace-primary"}
	if _, err := repository.ApplyDefinitionMutations(t.Context(), scope, mutations, nil, publication); err != nil {
		t.Fatal(err)
	}
	profilePayload, err := json.Marshal(identitymodel.IdentityProfileExtension{
		ObjectKey: "employee_profile", IdentityRelationField: "identity_user_id", Cardinality: "one_to_one",
		BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "employee"}, DefaultVisibility: "private",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ApplyDefinitionMutations(t.Context(), scope, []metadatamodel.MetadataDefinitionMutation{{
		Operation: "create", ResourceType: "identity_profile_binding", ResourceKey: "employee_profile",
		Request: metadatamodel.MetadataDefinitionUpsertRequest{SourceKind: "admin", SourceID: "gym-profile-bindings", Payload: profilePayload},
	}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	definitions, err := repository.ListDefinitions(t.Context(), scope, "role")
	if err != nil || len(definitions) != 4 {
		t.Fatalf("list applied roles count=%d err=%v", len(definitions), err)
	}
	if definitions[0].SchemaVersion != "1" {
		t.Fatalf("first applied schema version=%q", definitions[0].SchemaVersion)
	}
	profileDefinitions, err := repository.ListDefinitions(t.Context(), scope, "identity_profile_binding")
	if err != nil || len(profileDefinitions) != 1 || profileDefinitions[0].ResourceKey != "employee_profile" {
		t.Fatalf("shared profile-binding definitions=%#v err=%v", profileDefinitions, err)
	}
	var sharedRows int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _definitions WHERE installation_id='domainry-identity' AND owner='identity' AND kind IN ('role', 'identity_profile_binding')`).Scan(&sharedRows); err != nil || sharedRows != 5 {
		t.Fatalf("shared Identity definition rows=%d err=%v", sharedRows, err)
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
	profileDefinitions, err = restartedRepository.ListDefinitions(t.Context(), scope, "identity_profile_binding")
	if err != nil || len(profileDefinitions) != 1 || profileDefinitions[0].ResourceKey != "employee_profile" {
		t.Fatalf("list restarted profile bindings=%#v err=%v", profileDefinitions, err)
	}
}

func TestDirectRolePublicationRollbackAndDisableAreAtomicWithProjectionAndAudit(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseContext(t.Context()) })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	var retiredLocalizedTextTable int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_localized_texts'`).Scan(&retiredLocalizedTextTable); err != nil || retiredLocalizedTextTable != 0 {
		t.Fatalf("retired Identity localized-text table count=%d err=%v", retiredLocalizedTextTable, err)
	}
	var retiredRefreshIntentTable int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_metadata_refresh_intents'`).Scan(&retiredRefreshIntentTable); err != nil || retiredRefreshIntentTable != 0 {
		t.Fatalf("retired Identity metadata refresh-intent table count=%d err=%v", retiredRefreshIntentTable, err)
	}
	repository := NewMetadataStore(store, "workspace-primary")
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test direct role publication")
	publication := &metadatamodel.MetadataDefinitionPublication{WorkspaceID: "workspace-primary"}
	audit := func(id, event string) auditmodel.AuditEvent {
		return auditmodel.AuditEvent{ID: id, WorkspaceID: "workspace-primary", Family: auditmodel.EventFamilyIdentityGovernance, Event: event, ObjectKey: "role", RecordID: "reviewer", ActorID: "admin", RoleKey: "admin", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	payload := func(name string) json.RawMessage {
		raw, marshalErr := json.Marshal(identitymodel.RoleSchema{Key: "reviewer", Name: name, I18n: localizationmodel.LocalizedTextMap{"zh-CN": {"name": name + " zh"}}})
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
	assertSharedRoleLocalizedText(t, repository, "Senior Reviewer zh")
	assertRoleProjectionState(t, store, "Senior Reviewer", "active", 2)
	rolledBack, err := repository.RollbackDefinition(t.Context(), scope, "role", "reviewer", metadatamodel.MetadataDefinitionRollbackRequest{TargetVersion: "1", ExpectedSchemaHash: second.SchemaHash, BusinessReason: "restore"}, audit("audit-role-rollback", "metadata_definition.rolled_back"), publication)
	if err != nil {
		t.Fatal(err)
	}
	assertSharedRoleLocalizedText(t, repository, "Reviewer zh")
	assertRoleProjectionState(t, store, "Reviewer", "active", 3)
	if err := repository.DisableDefinition(t.Context(), scope, "role", "reviewer", strings.Repeat("0", 64), audit("audit-role-stale-disable", "metadata_definition.disabled"), publication); err == nil {
		t.Fatal("stale role disable was accepted")
	}
	assertRoleProjectionState(t, store, "Reviewer", "active", 3)
	if err := repository.DisableDefinition(t.Context(), scope, "role", "reviewer", rolledBack.SchemaHash, audit("audit-role-disable", "metadata_definition.disabled"), publication); err != nil {
		t.Fatal(err)
	}
	assertRoleProjectionState(t, store, "Reviewer", "disabled", 4)
	var disabled int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _definitions WHERE installation_id='domainry-identity' AND owner='identity' AND kind='role' AND definition_key='reviewer' AND disabled_at IS NOT NULL`).Scan(&disabled); err != nil || disabled != 1 {
		t.Fatalf("disabled role definitions=%d err=%v", disabled, err)
	}
}

func assertSharedRoleLocalizedText(t *testing.T, repository MetadataStore, want string) {
	t.Helper()
	values, err := repository.ListLocalizedTexts(t.Context(), "workspace-primary", metadatamodel.LocalizedTextQuery{
		WorkspaceID: "workspace-primary", EntityType: "role", EntityKey: "reviewer", Property: "name", Locale: "zh-CN",
	})
	if err != nil || len(values) != 1 || values[0].Text != want || values[0].SourceKind != "metadata_definition" {
		t.Fatalf("shared role localized texts=%#v err=%v", values, err)
	}
}

func assertRoleProjectionState(t *testing.T, store *database.IdentityStore, wantLabel, wantStatus string, wantAuditCount int) {
	t.Helper()
	var label, status string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT label, status FROM _identity_roles WHERE workspace_id=? AND role_key='reviewer'`, "workspace-primary").Scan(&label, &status); err != nil {
		t.Fatal(err)
	}
	if label != wantLabel || status != wantStatus {
		t.Fatalf("role projection label=%q status=%q want label=%q status=%q", label, status, wantLabel, wantStatus)
	}
	var audits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id=? AND object_key='role' AND record_id='reviewer'`, "workspace-primary").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != wantAuditCount {
		t.Fatalf("role audit count=%d want=%d", audits, wantAuditCount)
	}
}
