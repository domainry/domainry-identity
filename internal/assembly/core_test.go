package assembly

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

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
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assembled, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = assembled.CloseContext(t.Context()) })
	if assembled.Binding == nil {
		t.Fatal("binding-only assembly returned no SDK Binding")
	}
}

func TestAssemblySeparatesApplicationRegistrationFromPermissionReconcile(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", filepath.Join(t.TempDir(), "identity.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.CloseContext(t.Context()) })

	application := identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: "gym"}
	if _, err := core.Binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application, RedirectURLs: []string{"https://gym.example.test/callback"}}); err != nil {
		t.Fatalf("register application: %v", err)
	}
	permissionRequest, err := identitysdk.NewPermissionReconcileRequest(application, "application:gym", "", []identitysdk.PermissionDefinition{{PermissionKey: "access_session.read", ResourceKey: "access_session", OperationKey: "read", Label: "Read access sessions", Category: "Gym", SourceKind: "object_action"}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := core.Binding.Permissions().Reconcile(t.Context(), permissionRequest)
	if err != nil {
		t.Fatalf("reconcile application permission: %v", err)
	}
	if receipt.SourceOwner != "application:gym" || receipt.Inserted != 1 {
		t.Fatalf("permission receipt=%+v", receipt)
	}
	definitions, err := core.PermissionCatalog.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, definition := range definitions {
		found = found || definition.Key == "access_session.read" && definition.SourceOwner == "application:gym"
	}
	if !found {
		t.Fatalf("application-owned permission missing from current definitions: %+v", definitions)
	}
}

func TestColdStartLoadsPublishedRoleDefinitions(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", dbPath
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")

	open := func() *Core {
		store, err := database.OpenContext(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		core, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
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
	}}, nil, &metadatamodel.MetadataDefinitionPublication{WorkspaceID: cfg.IdentityWorkspaceID})
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
