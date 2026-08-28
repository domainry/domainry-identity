package assembly

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
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
	}}, nil, &changeplanmodel.BusinessChangePlanPublication{WorkspaceID: identitymodel.InstallationWorkspaceID, PlanID: "role-member"})
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
