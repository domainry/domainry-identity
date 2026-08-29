package migration

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type ReadDirFunc func(string) ([]os.DirEntry, error)

type PathResolver struct {
	engine  driver.Engine
	readDir ReadDirFunc
}

func NewPathResolver(engine driver.Engine, readDir ReadDirFunc) *PathResolver {
	if readDir == nil {
		readDir = os.ReadDir
	}
	return &PathResolver{engine: engine, readDir: readDir}
}

func (resolver *PathResolver) Paths(cfg config.Config) ([]string, error) {
	if strings.TrimSpace(cfg.MigrationSQL) != "" {
		return []string{cfg.MigrationSQL}, nil
	}
	driverDir := filepath.Join(cfg.MigrationDir, resolver.engine.Name())
	if entries, err := resolver.readDir(driverDir); err == nil {
		return SQLPaths(driverDir, entries), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	entries, err := resolver.readDir(cfg.MigrationDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return SQLPaths(cfg.MigrationDir, entries), nil
}
