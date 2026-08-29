package migration

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type StatusReader struct {
	database          driver.SchemaDatabase
	engine            driver.Engine
	renderer          ormdialect.Renderer
	config            config.Config
	expectedPaths     []string
	expectedChecksums map[string]string
}

func NewStatusReader(database driver.SchemaDatabase, engine driver.Engine, renderer ormdialect.Renderer, cfg config.Config) *StatusReader {
	return &StatusReader{database: database, engine: engine, renderer: renderer, config: cfg}
}

func (reader *StatusReader) ReplaceExpected(paths []string, checksums map[string]string) {
	reader.expectedPaths = append(reader.expectedPaths[:0], paths...)
	reader.expectedChecksums = make(map[string]string, len(checksums))
	for path, checksum := range checksums {
		reader.expectedChecksums[path] = checksum
	}
}

func (reader *StatusReader) Expected() ([]string, map[string]string) {
	paths := append([]string(nil), reader.expectedPaths...)
	checksums := make(map[string]string, len(reader.expectedChecksums))
	for path, checksum := range reader.expectedChecksums {
		checksums[path] = checksum
	}
	return paths, checksums
}

// MigrationStatus reports Identity database infrastructure state without
// exposing Store internals to transport or operations adapters.
func (reader *StatusReader) MigrationStatus(ctx context.Context) (MigrationStatus, error) {
	profilePolicy := reader.engine.MigrationRollbackPolicy()
	rollback := MigrationRollbackPolicy{
		Mode: profilePolicy.Mode, RequiresVerifiedBackup: profilePolicy.RequiresVerifiedBackup,
		Procedure: append([]string(nil), profilePolicy.Procedure...),
	}
	status := MigrationStatus{Current: true, State: StateCurrent, ServiceVersion: reader.config.ServiceVersion, ExpectedPaths: append([]string(nil), reader.expectedPaths...), Rollback: rollback}
	sort.Strings(status.ExpectedPaths)
	if len(status.ExpectedPaths) > 0 {
		status.MinSchemaVersion, _ = Identity(status.ExpectedPaths[0])
		status.MaxSchemaVersion, _ = Identity(status.ExpectedPaths[len(status.ExpectedPaths)-1])
	}
	if value := strings.TrimSpace(reader.config.DatabaseMinSchemaVersion); value != "" {
		status.MinSchemaVersion = value
	}
	if value := strings.TrimSpace(reader.config.DatabaseMaxSchemaVersion); value != "" {
		status.MaxSchemaVersion = value
	}
	status.Expected = len(status.ExpectedPaths)
	applied := map[string]struct{}{}
	currentSchemaVersion := ""
	rows, err := reader.database.QueryContext(ctx, "SELECT "+reader.renderer.Identifier("path")+", "+reader.renderer.Identifier("checksum")+", "+reader.renderer.Identifier("dirty")+", "+reader.renderer.Identifier("applied_at")+" FROM "+reader.renderer.Table("_schema_migrations")+" ORDER BY "+reader.renderer.Identifier("path")+" ASC")
	if err != nil {
		status.Current = false
		return status, fmt.Errorf("read migration status: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var path, checksum, at string
		var dirty bool
		if err := rows.Scan(&path, &checksum, &dirty, &at); err != nil {
			status.Current = false
			return status, fmt.Errorf("scan migration status: %w", err)
		}
		status.AppliedPaths = append(status.AppliedPaths, path)
		applied[path] = struct{}{}
		if expected, tracked := reader.expectedChecksums[path]; tracked {
			version, _ := Identity(filepath.Base(path))
			if currentSchemaVersion == "" || CompareVersions(version, currentSchemaVersion) > 0 {
				currentSchemaVersion = version
			}
			if checksum != expected {
				status.DriftPaths = append(status.DriftPaths, path)
			}
		} else {
			version, _ := Identity(filepath.Base(path))
			if status.MaxSchemaVersion != "" && CompareVersions(version, status.MaxSchemaVersion) > 0 {
				status.NewerPaths = append(status.NewerPaths, path)
			} else {
				status.UnknownPaths = append(status.UnknownPaths, path)
			}
		}
		if dirty {
			status.DirtyPaths = append(status.DirtyPaths, path)
		}
		if at > status.LastAppliedAt {
			status.LastAppliedAt = at
		}
	}
	if err := rows.Err(); err != nil {
		status.Current = false
		return status, fmt.Errorf("read migration rows: %w", err)
	}
	status.Applied = len(status.AppliedPaths)
	for _, path := range status.ExpectedPaths {
		if _, ok := applied[path]; !ok {
			status.PendingPaths = append(status.PendingPaths, path)
		}
	}
	status.Pending = len(status.PendingPaths)
	status.Drift = len(status.DriftPaths)
	status.Dirty = len(status.DirtyPaths)
	status.Unknown = len(status.UnknownPaths)
	status.Newer = len(status.NewerPaths)
	if currentSchemaVersion != "" && status.MinSchemaVersion != "" && CompareVersions(currentSchemaVersion, status.MinSchemaVersion) < 0 && status.Pending == 0 {
		status.Pending = 1
	}
	if currentSchemaVersion != "" && status.MaxSchemaVersion != "" && CompareVersions(currentSchemaVersion, status.MaxSchemaVersion) > 0 && status.Newer == 0 {
		status.Newer = 1
		status.NewerPaths = append(status.NewerPaths, currentSchemaVersion)
	}
	switch {
	case status.Dirty > 0:
		status.State, status.ErrorCode = StateDirty, StateDirty
	case status.Drift > 0:
		status.State, status.ErrorCode = StateDrift, StateDrift
	case status.Newer > 0:
		status.State, status.ErrorCode = StateNewer, StateNewer
	case status.Unknown > 0:
		status.State, status.ErrorCode = StateUnknown, StateUnknown
	case status.Pending > 0:
		status.State, status.ErrorCode = StatePending, StatePending
	}
	status.Current = status.State == StateCurrent
	return status, nil
}
