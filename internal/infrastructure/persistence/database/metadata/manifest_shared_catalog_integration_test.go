package metadata

import (
	"path/filepath"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestManifestCatalogUsesSharedDefinitionsAndOperations(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.CloseContext(t.Context()) })
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	bindTestModuleDependencies(t, store)
	repository := NewMetadataStore(store, "workspace-primary")
	manifest := manifestmodel.ManifestSchema{
		TemplateID: "identity-template", Version: "7", Name: "Identity Template", DefaultLocale: "zh-CN",
		Roles: []identitymodel.RoleSchema{{Key: "reviewer", Name: "Reviewer"}},
	}
	if err := repository.EnsureManifestMetadata(t.Context(), manifest); err != nil {
		t.Fatal(err)
	}
	scope := identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "read shared manifest catalog")
	loaded, err := repository.LoadManifest(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TemplateID != manifest.TemplateID || loaded.Version != manifest.Version || loaded.Name != manifest.Name || loaded.DefaultLocale != manifest.DefaultLocale {
		t.Fatalf("loaded shared manifest identity=%#v", loaded)
	}
	revision, err := repository.SnapshotRevision(t.Context(), scope)
	if err != nil || len(revision) != 64 {
		t.Fatalf("shared Definition revision=%q err=%v", revision, err)
	}
	if err := repository.SetManifestIdentitySeedSyncedVersion(t.Context(), "seed-v1"); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetManifestIdentitySeedSyncedVersion(t.Context(), "seed-v2"); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := repository.ManifestIdentitySeedSyncedVersion(t.Context())
	if err != nil || checkpoint != "seed-v2" {
		t.Fatalf("shared Operation checkpoint=%q err=%v", checkpoint, err)
	}
	var operationRows int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id='workspace-primary' AND owner='identity' AND kind='identity.manifest_seed_checkpoint'`).Scan(&operationRows); err != nil || operationRows != 1 {
		t.Fatalf("manifest seed checkpoint operation rows=%d err=%v", operationRows, err)
	}
	var retiredCatalogTables int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_manifest_catalog'`).Scan(&retiredCatalogTables); err != nil || retiredCatalogTables != 0 {
		t.Fatalf("retired manifest catalog tables=%d err=%v", retiredCatalogTables, err)
	}
}
