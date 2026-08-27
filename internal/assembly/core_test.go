package assembly

import (
	"path/filepath"
	"runtime"
	"testing"

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
