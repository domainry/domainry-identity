package module

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

// Options configures both the deployment-neutral Identity application graph
// and its in-process Binding. The module owns its persistence lifecycle and
// never borrows Runtime infrastructure.
type Options struct {
	// ProjectConfigurationPath optionally points to a Git-owned, non-secret
// Identity project configuration file. Secrets remain environment-owned.
	ProjectConfigurationPath string
	IdentityVersion          string
	DatabaseDriver           string
	DatabaseDSN              string
	DatabaseMigrationDSN     string
	DatabaseSchema           string
	DatabasePath             string
	// Clock is an optional module-local infrastructure override, primarily for
	// deterministic tests. The embedding Runtime does not supply it.
	Clock identitysdk.Clock
}

// OptionsFromEnvironment supplies standalone defaults. A Runtime host using
// OpenWithDatabase overrides these values with its project-owned pool.
func OptionsFromEnvironment() Options {
	return Options{
		ProjectConfigurationPath: strings.TrimSpace(os.Getenv("IDENTITY_MODULE_PROJECT_CONFIG")),
		IdentityVersion:          strings.TrimSpace(os.Getenv("DOMAINRY_IDENTITY_VERSION")),
		DatabaseDriver:           moduleEnvironmentValue("IDENTITY_MODULE_DATABASE_DRIVER", "sqlite"),
		DatabaseDSN:              strings.TrimSpace(os.Getenv("IDENTITY_MODULE_DATABASE_DSN")),
		DatabaseMigrationDSN:     strings.TrimSpace(os.Getenv("IDENTITY_MODULE_DATABASE_MIGRATION_DSN")),
		DatabaseSchema:           strings.TrimSpace(os.Getenv("IDENTITY_MODULE_DATABASE_SCHEMA")),
		DatabasePath:             moduleEnvironmentValue("IDENTITY_MODULE_DB_PATH", "data/identity-module.db"),
	}
}

//go:embed default_manifest.json
var defaultManifestJSON []byte

func loadModuleConfig(options Options) (config.Config, config.Snapshot, error) {
	cfg, snapshot, err := config.LoadWithProjectFile(strings.TrimSpace(options.ProjectConfigurationPath))
	if err != nil {
		return config.Config{}, config.Snapshot{}, err
	}
	if version := strings.TrimSpace(options.IdentityVersion); version != "" {
		cfg.ServiceVersion = version
	}
	// Always override process-global Runtime persistence. The zero-value module
	// options still select an isolated SQLite database for local development.
	cfg.DatabaseDriver = moduleOptionValue(options.DatabaseDriver, "sqlite")
	cfg.DatabaseDSN = strings.TrimSpace(options.DatabaseDSN)
	cfg.DatabaseMigrationDSN = strings.TrimSpace(options.DatabaseMigrationDSN)
	cfg.DatabaseSchema = strings.TrimSpace(options.DatabaseSchema)
	cfg.DBPath = moduleOptionValue(options.DatabasePath, "data/identity-module.db")
	return cfg, snapshot, nil
}

func moduleEnvironmentValue(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func moduleOptionValue(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func loadModuleManifest() (manifestmodel.ManifestSchema, error) {
	manifest, _, err := manifestmodel.DecodeManifest(defaultManifestJSON)
	if err != nil {
		return manifestmodel.ManifestSchema{}, fmt.Errorf("decode embedded Identity module manifest: %w", err)
	}
	// Keep the embed visibly valid to static tooling even when DecodeManifest's
	// implementation changes away from encoding/json.
	if !json.Valid(defaultManifestJSON) {
		return manifestmodel.ManifestSchema{}, fmt.Errorf("embedded Identity module manifest is invalid JSON")
	}
	return manifest, nil
}
