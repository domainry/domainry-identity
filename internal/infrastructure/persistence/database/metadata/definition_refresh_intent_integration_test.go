package metadata

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestPublishDefinitionUsesIdentityOwnedRefreshIntent(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	repository := NewMetadataStore(store, "workspace-primary")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	definition, err := repository.PublishDefinition(
		t.Context(),
		identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test metadata publication"),
		"role",
		"order_reviewer",
		metadatamodel.MetadataDefinitionUpsertRequest{
			Name:       "Order Reviewer",
			SourceKind: "test",
			SourceID:   "definition-refresh-intent-test",
			Payload:    json.RawMessage(`{"key":"order_reviewer","name":"Order Reviewer","record_scope":"all_records"}`),
		},
		auditmodel.AuditEvent{
			ID:          "audit-metadata-order",
			WorkspaceID: "workspace-primary",
			Event:       "metadata_definition.saved",
			ObjectKey:   "role",
			RecordID:    "order_reviewer",
			ActorID:     "test",
			RoleKey:     "system",
			CreatedAt:   now,
		},
		&metadatamodel.MetadataDefinitionPublication{WorkspaceID: "workspace-primary"},
	)
	if err != nil {
		t.Fatal(err)
	}

	var status, operation string
	if err := store.DB().QueryRowContext(t.Context(),
		"SELECT status, operation FROM _identity_metadata_refresh_intents WHERE workspace_id = ? AND idempotency_key = ?",
		"workspace-primary",
		definition.SchemaHash,
	).Scan(&status, &operation); err != nil {
		t.Fatal(err)
	}
	if status != "executing" || operation != "catalog_refresh" {
		t.Fatalf("refresh intent status=%q operation=%q", status, operation)
	}

	if err := repository.CompleteDefinitionRefresh(
		t.Context(),
		identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test metadata refresh completion"),
		definition.ResourceType,
		definition.ResourceKey,
		definition.SchemaHash,
		"",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(t.Context(),
		"SELECT status FROM _identity_metadata_refresh_intents WHERE workspace_id = ? AND idempotency_key = ?",
		"workspace-primary",
		definition.SchemaHash,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatalf("completed refresh intent status=%q", status)
	}
}
