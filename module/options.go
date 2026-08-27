package module

import (
	"strings"

	"github.com/domainry/domainry-identity/internal/platform/config"
)

// Options configures both the deployment-neutral Identity application graph
// and its in-process Binding. Database ownership remains with modulehost.Host.
type Options struct {
	// ProjectConfigurationPath optionally points to a Git-owned, non-secret
	// Identity project configuration file. Secrets remain environment-owned.
	ProjectConfigurationPath string
	IdentityVersion          string
}

func loadModuleConfig(options Options) (config.Config, config.Snapshot, error) {
	cfg, snapshot, err := config.LoadWithProjectFile(strings.TrimSpace(options.ProjectConfigurationPath))
	if err != nil {
		return config.Config{}, config.Snapshot{}, err
	}
	if version := strings.TrimSpace(options.IdentityVersion); version != "" {
		cfg.ServiceVersion = version
	}
	return cfg, snapshot, nil
}
