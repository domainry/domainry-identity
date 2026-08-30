package portability_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	portabilitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/portability"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestEmbeddedWorkspaceExportImportIsDeterministicAndSecretFree(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	source := openIdentityStore(t, "source.db")
	seedPortableWorkspace(t, source, now)
	sourceRepository, err := portabilitypersistence.NewSQLRepository(source)
	if err != nil {
		t.Fatal(err)
	}
	sourceService, err := portabilityapplication.NewService(sourceRepository, portabilityapplication.Options{
		Clock: func() time.Time { return now }, SchemaVersion: database.CurrentIdentitySchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	dryRun, err := sourceService.Export(t.Context(), portabilityapplication.ExportRequest{WorkspaceID: "workspace-a", SourceMode: "module", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dryRun.Bundle != nil || dryRun.Inventory.DatasetCounts["users"] != 1 || dryRun.Inventory.ExcludedCounts["credentials"] != 1 || dryRun.Inventory.ExcludedCounts["provider_secrets"] != 1 {
		t.Fatalf("unexpected dry-run inventory: %+v", dryRun)
	}
	if _, err := sourceService.Export(t.Context(), portabilityapplication.ExportRequest{WorkspaceID: "workspace-a", SourceMode: "module"}); err == nil || !strings.Contains(err.Error(), "write_freeze_not_active") {
		t.Fatalf("unfrozen export was accepted: %v", err)
	}
	if fence, err := sourceService.FreezeWrites(t.Context(), "workspace-a", "freeze-ticket-42", "migration-operator"); err != nil || fence.State != "frozen" {
		t.Fatalf("write fence=%+v err=%v", fence, err)
	}
	if fence, err := sourceService.FreezeWrites(t.Context(), "workspace-a", "freeze-ticket-42", "another-operator"); err != nil || fence.State != "frozen" || fence.FrozenBy != "migration-operator" {
		t.Fatalf("idempotent write fence=%+v err=%v", fence, err)
	}
	if _, err := sourceService.FreezeWrites(t.Context(), "workspace-a", "different-ticket", "migration-operator"); err == nil || !strings.Contains(err.Error(), "write_fence_already_active") {
		t.Fatalf("active fence was overwritten: %v", err)
	}
	assertWriteFenceEvents(t, source, 1, "frozen")

	exported, err := sourceService.Export(t.Context(), portabilityapplication.ExportRequest{
		WorkspaceID: "workspace-a", SourceMode: "module",
	})
	if err != nil {
		t.Fatal(err)
	}
	if exported.Bundle == nil || exported.Bundle.ContentSHA256 == "" {
		t.Fatalf("missing export bundle: %+v", exported)
	}
	raw, err := json.Marshal(exported.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password_hash", "refresh-token-secret", "provider-secret-envelope"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("portable bundle leaked %q: %s", forbidden, raw)
		}
	}
	if len(exported.Bundle.ProviderReferences) != 1 || exported.Bundle.ProviderReferences[0].ProviderKey != "oidc" || !exported.Bundle.ProviderReferences[0].SecretRequired {
		t.Fatalf("provider references=%+v", exported.Bundle.ProviderReferences)
	}

	repeated, err := sourceService.Export(t.Context(), portabilityapplication.ExportRequest{
		WorkspaceID: "workspace-a", SourceMode: "module",
	})
	if err != nil || repeated.Bundle.ContentSHA256 != exported.Bundle.ContentSHA256 || repeated.Bundle.ExportID != exported.Bundle.ExportID {
		t.Fatalf("repeated export=%+v err=%v", repeated.Bundle, err)
	}

	target := openIdentityStore(t, "target.db")
	targetRepository, err := portabilitypersistence.NewSQLRepository(target)
	if err != nil {
		t.Fatal(err)
	}
	seedTargetProvider(t, target, now)
	targetService, err := portabilityapplication.NewService(targetRepository, portabilityapplication.Options{
		Clock: func() time.Time { return now.Add(time.Minute) }, SchemaVersion: database.CurrentIdentitySchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := portabilityapplication.ImportRequest{Bundle: *exported.Bundle, IdempotencyKey: "cutover-42"}
	dryImport := request
	dryImport.DryRun = true
	if result, err := targetService.Import(t.Context(), dryImport); err != nil || result.Receipt != nil {
		t.Fatalf("dry import result=%+v err=%v", result, err)
	}
	result, err := targetService.Import(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt == nil || result.Receipt.ImportedCounts["users"] != 1 || !result.Receipt.AuthorizationOK || !result.Receipt.SessionsRevoked || !result.Receipt.CredentialsReset || !result.Receipt.MFAReenrollment {
		t.Fatalf("import receipt=%+v", result.Receipt)
	}
	var users, credentials, sessions, providerCredentials int
	for query, countDestination := range map[string]*int{
		`SELECT COUNT(*) FROM _identity_users WHERE workspace_id='workspace-a'`:                     &users,
		`SELECT COUNT(*) FROM _identity_credentials WHERE workspace_id='workspace-a'`:               &credentials,
		`SELECT COUNT(*) FROM _identity_auth_refresh_tokens WHERE workspace_id='workspace-a'`:       &sessions,
		`SELECT COUNT(*) FROM _identity_auth_provider_credentials WHERE workspace_id='workspace-a'`: &providerCredentials,
	} {
		if err := target.DB().QueryRowContext(t.Context(), query).Scan(countDestination); err != nil {
			t.Fatal(err)
		}
	}
	if users != 1 || credentials != 0 || sessions != 0 || providerCredentials != 1 {
		t.Fatalf("imported users=%d credentials=%d sessions=%d provider_credentials=%d", users, credentials, sessions, providerCredentials)
	}
	replay, err := targetService.Import(t.Context(), request)
	if err != nil || replay.Receipt == nil || !replay.Receipt.Replayed {
		t.Fatalf("replay=%+v err=%v", replay.Receipt, err)
	}
	if _, err := target.DB().ExecContext(t.Context(), `UPDATE _identity_roles SET label='Tampered' WHERE workspace_id='workspace-a' AND id='role-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := targetService.Import(t.Context(), request); err == nil || !strings.Contains(err.Error(), "authorization_parity_failed") {
		t.Fatalf("tampered target replay accepted: %v", err)
	}
	if fence, err := sourceService.ReleaseWriteFence(t.Context(), "workspace-a", "rollback-operator"); err != nil || fence.State != "released" || fence.ReleasedBy != "rollback-operator" {
		t.Fatalf("released fence=%+v err=%v", fence, err)
	}
	assertWriteFenceEvents(t, source, 2, "released")
}

func assertWriteFenceEvents(t *testing.T, store *database.IdentityStore, wantCount int, wantEvent string) {
	t.Helper()
	var count int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id='workspace-a' AND object_key='_identity_workspace_write_fences'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != wantCount {
		t.Fatalf("write-fence event count=%d want=%d", count, wantCount)
	}
	var matching int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id='workspace-a' AND object_key='_identity_workspace_write_fences' AND event=?`, "identity.portability_write_fence."+wantEvent).Scan(&matching); err != nil {
		t.Fatal(err)
	}
	if matching != 1 {
		t.Fatalf("write-fence event %q count=%d want=1", wantEvent, matching)
	}
}

func TestImportRejectsMissingCutoverEvidence(t *testing.T) {
	bundle := portabilitymodel.Bundle{}
	if err := bundle.Finalize(); err == nil {
		t.Fatal("invalid portability bundle was finalized")
	}
}

func openIdentityStore(t *testing.T, name string) *database.IdentityStore {
	t.Helper()
	store, err := database.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), name),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	return store
}

func seedPortableWorkspace(t *testing.T, store *database.IdentityStore, now time.Time) {
	t.Helper()
	timestamp := now.Format(time.RFC3339Nano)
	seedMetadataSchemaHash(t, store)
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_users
        (id, workspace_id, name, given_name, middle_name, family_name, name_prefix, name_suffix, native_name, name_locale, email, phone, account_type, locale, timezone, status, version, created_at, updated_at)
        VALUES (?, ?, ?, '', '', '', '', '', '', '', ?, '', 'human', '', '', 'active', 1, ?, ?)`,
		"user-1", "workspace-a", "User One", "user@example.com", timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_roles
        (id, workspace_id, role_key, label, description, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, '', 'active', ?, ?)`, "role-1", "workspace-a", "reader", "Reader", timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_user_role_assignments
        (id, workspace_id, user_id, role_id, workforce_profile_id, binding_key, profile_id, source, status, valid_from, valid_until, granted_by, grant_reason, revoked_by, revoked_at, revoke_reason, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, NULL, NULL, NULL, 'manual', 'active', NULL, NULL, 'admin', '', NULL, NULL, NULL, NULL, ?, ?)`,
		"assignment-1", "workspace-a", "user-1", "role-1", timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_credentials
        (user_id, workspace_id, password_hash, password_updated_at, failed_login_count, locked_until, last_login_at, must_change_password, created_at, updated_at)
        VALUES (?, ?, ?, ?, 0, NULL, NULL, 0, ?, ?)`, "user-1", "workspace-a", "password_hash", timestamp, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_auth_refresh_tokens
        (id, workspace_id, user_id, session_id, audience, token_hash, expires_at, revoked_at, replaced_by_id, last_used_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'runtime', ?, ?, NULL, NULL, NULL, ?, ?)`,
		"refresh-1", "workspace-a", "user-1", "session-1", "refresh-token-secret", now.Add(time.Hour).Format(time.RFC3339Nano), timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	providerConfiguration := `{"provider_key":"oidc","workspace_id":"workspace-a","type":"oidc","issuer":"https://issuer.example","client_id":"client-a","auto_create_users":false}`
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_auth_provider_credentials
        (workspace_id, provider_key, configuration_json, secret_envelope, updated_by, created_at, updated_at)
        VALUES (?, 'oidc', ?, 'provider-secret-envelope', 'admin', ?, ?)`, "workspace-a", providerConfiguration, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
}

func seedTargetProvider(t *testing.T, store *database.IdentityStore, now time.Time) {
	t.Helper()
	seedMetadataSchemaHash(t, store)
	timestamp := now.Format(time.RFC3339Nano)
	providerConfiguration := `{"provider_key":"oidc","workspace_id":"workspace-a","type":"oidc","issuer":"https://issuer.example","client_id":"saas-client","auto_create_users":false}`
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_auth_provider_credentials
        (workspace_id, provider_key, configuration_json, secret_envelope, updated_by, created_at, updated_at)
        VALUES (?, 'oidc', ?, 'target-provider-secret-envelope', 'operator', ?, ?)`, "workspace-a", providerConfiguration, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
}

func seedMetadataSchemaHash(t *testing.T, store *database.IdentityStore) {
	t.Helper()
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_manifest_catalog (key, value, updated_at) VALUES ('schema_hash', ?, '2026-08-27T12:00:00Z')`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}
