package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
)

const CurrentIdentityWorkspaceRLSPolicyVersion = "v1"

type WorkspaceRLSStatus = driver.WorkspaceRLSStatus

func (s *IdentityStore) WorkspaceRLSStatus(_ context.Context) WorkspaceRLSStatus {
	status := s.workspaceRLS
	status.CoveredTables = append([]string(nil), status.CoveredTables...)
	status.MissingTables = append([]string(nil), status.MissingTables...)
	return status
}

// EnsureWorkspaceRLS delegates engine-specific policy management to the
// selected profile. Repository workspace predicates remain the primary
// isolation boundary for every database engine.
func (s *IdentityStore) EnsureWorkspaceRLS(ctx context.Context) error {
	if s == nil {
		return nil
	}
	base := s.sqlBase()
	if !s.config.DatabaseRLSEnabled || !base.Engine.WorkspaceRLSSupported() {
		s.workspaceRLS = WorkspaceRLSStatus{}
		return nil
	}
	applicationRole := strings.TrimSpace(s.postgresCapabilities.User)
	if s.postgresProfile == nil {
		return fmt.Errorf("workspace RLS requires a PostgreSQL connection profile")
	}
	if s.config.EffectiveDatabaseMigrationMode() == "apply" {
		if s.migrationDB == nil {
			return fmt.Errorf("workspace RLS apply requires the migration connection")
		}
		if err := base.Engine.ApplyWorkspaceRLS(ctx, s.migrationDB, base.SQLRenderer, base.DatabaseSchema, applicationRole, CurrentIdentityWorkspaceRLSPolicyVersion); err != nil {
			return err
		}
	}
	status, err := base.Engine.InspectWorkspaceRLS(ctx, s.db, base.SQLRenderer, base.DatabaseSchema, applicationRole, CurrentIdentityWorkspaceRLSPolicyVersion)
	if err != nil {
		return err
	}
	s.workspaceRLS = status
	if len(status.MissingTables) > 0 {
		return fmt.Errorf("workspace RLS policy coverage is incomplete: %s", strings.Join(status.MissingTables, ", "))
	}
	return nil
}
