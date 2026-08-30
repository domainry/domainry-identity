package assembly

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestBindingRuntimeAssemblyReturnsDirectSDKBinding(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assembled, err := New(t.Context(), cfg, store, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = assembled.CloseContext(t.Context()) })
	if assembled.Binding == nil {
		t.Fatal("binding-only assembly returned no SDK Binding")
	}
}

func TestPublishedRuntimeCatalogParticipatesInRoleCandidateValidation(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", filepath.Join(t.TempDir(), "identity.db")
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, err := New(t.Context(), cfg, store, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.CloseContext(t.Context()) })

	workspaceID := identitysdk.WorkspaceID(identitymodel.InstallationWorkspaceID)
	ctx := requestcontext.WithWorkspaceID(t.Context(), identitymodel.InstallationWorkspaceID)
	_, err = core.Binding.Catalog().Publish(ctx, identitysdk.AuthorizationCatalog{
		ContractVersion: identitysdk.CatalogVersionV1,
		Application:     identitysdk.ApplicationRef{WorkspaceID: workspaceID, ApplicationKey: "gym"},
		Resources:       []identitysdk.ResourceDefinition{{Key: "access_session", Fields: []string{"id", "member_id"}, SupportedFacts: []string{"id"}}},
		Actions:         []identitysdk.ActionDefinition{{Resource: "access_session", Action: "read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"key":"member","name":"Member","permissions":["access_session.read"],"record_scope":"all_records","data_permissions":[{"object_key":"access_session","scope":"all_records","read":true}]}`)
	mutation := metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: "member", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: payload}}
	if err := core.Metadata.ValidateMetadataCandidate(ctx, []metadatamodel.MetadataDefinitionMutation{mutation}); err != nil {
		t.Fatalf("Runtime catalog object rejected by role candidate validation: %#v", err)
	}
}

func TestColdStartLoadsPublishedRoleDefinitions(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", dbPath
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")

	open := func() *Core {
		store, err := database.OpenContext(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		core, err := New(t.Context(), cfg, store, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return core
	}
	first := open()
	payload, _ := json.Marshal(identitymodel.RoleSchema{Key: "member", Name: "Member", Permissions: []string{"membership.read", "booking.create"}, RecordScope: "all_records"})
	empty := ""
	_, err := first.MetadataStore.ApplyDefinitionMutations(t.Context(), identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test published role"), []metadatamodel.MetadataDefinitionMutation{{
		Operation: "create", ResourceType: "role", ResourceKey: "member",
		Request: metadatamodel.MetadataDefinitionUpsertRequest{ExpectedSchemaHash: &empty, Payload: payload},
	}}, nil, &metadatamodel.MetadataDefinitionPublication{WorkspaceID: identitymodel.InstallationWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	second := open()
	defer second.CloseContext(t.Context())
	definition, found := second.Identity.PublishedRoleDefinition(t.Context(), "member")
	if !found || len(definition.Permissions) != 2 || definition.Permissions[0] != "membership.read" {
		t.Fatalf("cold-start role definition=%#v found=%v", definition, found)
	}
	found = false
	for _, role := range second.MetadataRuntime.Schema().Roles {
		found = found || role.Key == "member"
	}
	if !found {
		t.Fatal("cold-start metadata snapshot omitted published member role")
	}
}
