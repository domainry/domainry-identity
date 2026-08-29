package workspace

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

const CurrentIdentityWorkspaceRLSPolicyVersion = "v1"

type WorkspaceRLSStatus = driver.WorkspaceRLSStatus

type RLSManager struct {
	db                   *sql.DB
	migrationDB          *sql.DB
	engine               driver.Engine
	renderer             ormdialect.Renderer
	databaseSchema       string
	applicationRole      string
	enabled              bool
	apply                bool
	connectionProfileSet bool
	status               WorkspaceRLSStatus
}

type RLSOptions struct {
	Database             *sql.DB
	MigrationDatabase    *sql.DB
	Engine               driver.Engine
	Renderer             ormdialect.Renderer
	DatabaseSchema       string
	ApplicationRole      string
	Enabled              bool
	Apply                bool
	ConnectionProfileSet bool
	Status               WorkspaceRLSStatus
}

func NewRLSManager(options RLSOptions) *RLSManager {
	return &RLSManager{
		db: options.Database, migrationDB: options.MigrationDatabase, engine: options.Engine,
		renderer: options.Renderer, databaseSchema: options.DatabaseSchema,
		applicationRole: strings.TrimSpace(options.ApplicationRole), enabled: options.Enabled,
		apply: options.Apply, connectionProfileSet: options.ConnectionProfileSet, status: options.Status,
	}
}

func (manager *RLSManager) WorkspaceRLSStatus(_ context.Context) WorkspaceRLSStatus {
	if manager == nil {
		return WorkspaceRLSStatus{}
	}
	status := manager.status
	status.CoveredTables = append([]string(nil), status.CoveredTables...)
	status.MissingTables = append([]string(nil), status.MissingTables...)
	return status
}

// EnsureWorkspaceRLS delegates engine-specific policy management to the
// selected profile. Repository workspace predicates remain the primary
// isolation boundary for every database engine.
func (manager *RLSManager) EnsureWorkspaceRLS(ctx context.Context) error {
	if manager == nil {
		return nil
	}
	if !manager.enabled || !manager.engine.WorkspaceRLSSupported() {
		manager.status = WorkspaceRLSStatus{}
		return nil
	}
	if !manager.connectionProfileSet {
		return fmt.Errorf("workspace RLS requires a PostgreSQL connection profile")
	}
	if manager.apply {
		if manager.migrationDB == nil {
			return fmt.Errorf("workspace RLS apply requires the migration connection")
		}
		if err := manager.engine.ApplyWorkspaceRLS(ctx, manager.migrationDB, manager.renderer, manager.databaseSchema, manager.applicationRole, CurrentIdentityWorkspaceRLSPolicyVersion); err != nil {
			return err
		}
	}
	status, err := manager.engine.InspectWorkspaceRLS(ctx, manager.db, manager.renderer, manager.databaseSchema, manager.applicationRole, CurrentIdentityWorkspaceRLSPolicyVersion)
	if err != nil {
		return err
	}
	manager.status = status
	if len(status.MissingTables) > 0 {
		return fmt.Errorf("workspace RLS policy coverage is incomplete: %s", strings.Join(status.MissingTables, ", "))
	}
	return nil
}
