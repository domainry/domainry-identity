package metadata

import (
	"encoding/json"
	"path/filepath"
	"testing"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
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
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test Change Plan role publication")
	store, repository := open()
	mutations := make([]metadatamodel.MetadataDefinitionMutation, 0, 4)
	for _, key := range []string{"member", "coach", "store_manager", "finance"} {
		payload, err := json.Marshal(identitymodel.RoleSchema{Key: key, Name: key, RecordScope: "all_records", DataPermissions: []identitymodel.DataPermission{{ObjectKey: "booking", Scope: "all_records", Read: true}}})
		if err != nil {
			t.Fatal(err)
		}
		mutations = append(mutations, metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: key, Request: metadatamodel.MetadataDefinitionUpsertRequest{SourceKind: "admin", SourceID: "gym-roles", Payload: payload}})
	}
	publication := &changeplanmodel.BusinessChangePlanPublication{WorkspaceID: identitymodel.InstallationWorkspaceID, PlanID: "gym-role-publication"}
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
