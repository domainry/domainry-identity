package metadata

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
	"github.com/domainry/domainry-orm/query"
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
			Payload:    json.RawMessage(`{"key":"order_reviewer","name":"Order Reviewer"}`),
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
		definition.SchemaVersion+":"+definition.SchemaHash,
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
		definition.SchemaVersion,
		definition.SchemaHash,
		"",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(t.Context(),
		"SELECT status FROM _identity_metadata_refresh_intents WHERE workspace_id = ? AND idempotency_key = ?",
		"workspace-primary",
		definition.SchemaVersion+":"+definition.SchemaHash,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatalf("completed refresh intent status=%q", status)
	}
}

func TestRepublishingOldRoleContentHasIndependentRefreshAndCompletion(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err = store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	repository := NewMetadataStore(store, "workspace-primary")
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test permission restore refresh")
	publication := &metadatamodel.MetadataDefinitionPublication{WorkspaceID: "workspace-primary"}
	var definitions []metadatamodel.MetadataDefinition
	for index, name := range []string{"Allowed", "Revoked", "Allowed"} {
		payload, _ := json.Marshal(map[string]any{"key": "reviewer", "name": name})
		request := metadatamodel.MetadataDefinitionUpsertRequest{Payload: payload}
		if index > 0 {
			expected := definitions[index-1].SchemaHash
			request.ExpectedSchemaHash = &expected
		}
		definition, err := repository.PublishDefinition(t.Context(), scope, "role", "reviewer", request, auditmodel.AuditEvent{ID: fmt.Sprintf("restore-%d", index), WorkspaceID: "workspace-primary", Event: "metadata_definition.saved", ObjectKey: "role", RecordID: "reviewer", ActorID: "test", RoleKey: "system", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}, publication)
		if err != nil {
			t.Fatalf("publication %d: %v", index, err)
		}
		definitions = append(definitions, definition)
	}
	first, restored := definitions[0], definitions[2]
	if first.SchemaHash != restored.SchemaHash || first.SchemaVersion == restored.SchemaVersion {
		t.Fatal("fixture did not restore the same content as a new revision")
	}
	if err = repository.CompleteDefinitionRefresh(t.Context(), scope, first.ResourceType, first.ResourceKey, first.SchemaVersion, first.SchemaHash, ""); err != nil {
		t.Fatal(err)
	}
	status := func(d metadatamodel.MetadataDefinition) string {
		t.Helper()
		statement, args, err := query.NewSelectBuilder(store.SQLRenderer, metadataRefreshIntentTable).Columns("status").Where(query.And(query.Equal("workspace_id", "workspace-primary"), query.Equal("id", metadataDefinitionRefreshIntentID(d.ResourceType, d.ResourceKey, d.SchemaVersion, d.SchemaHash)))).Build()
		if err != nil {
			t.Fatal(err)
		}
		var out string
		if err = store.DB().QueryRowContext(t.Context(), statement, args...).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if status(first) != "succeeded" || status(restored) != "executing" {
		t.Fatal("late completion consumed a later publication")
	}
	if err = repository.CompleteDefinitionRefresh(t.Context(), scope, first.ResourceType, first.ResourceKey, first.SchemaVersion, first.SchemaHash, "late failure"); err == nil {
		t.Fatal("closed old publication reopened")
	}
	if status(restored) != "executing" {
		t.Fatal("old completion changed current publication")
	}
	if err = repository.CompleteDefinitionRefresh(t.Context(), scope, restored.ResourceType, restored.ResourceKey, restored.SchemaVersion, restored.SchemaHash, ""); err != nil {
		t.Fatal(err)
	}
	if status(restored) != "succeeded" {
		t.Fatal("restored publication not completed")
	}
}
