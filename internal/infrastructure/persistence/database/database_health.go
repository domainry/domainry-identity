package database

import (
	"context"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
)

type databaseHealthProfile interface {
	Status(*IdentityStore) (postgres.SafeStatus, bool)
	Readiness(*IdentityStore) DatabaseReadiness
}

type portableDatabaseHealth struct{}

func (portableDatabaseHealth) Status(*IdentityStore) (postgres.SafeStatus, bool) {
	return postgres.SafeStatus{}, false
}
func (portableDatabaseHealth) Readiness(store *IdentityStore) DatabaseReadiness {
	ready := store != nil && store.db != nil
	return DatabaseReadiness{Ready: ready, ReadReady: ready, WriteReady: ready, MigrationCompatible: ready}
}

type postgresDatabaseHealth struct{}

func (postgresDatabaseHealth) Status(store *IdentityStore) (postgres.SafeStatus, bool) {
	if store == nil || store.postgresProfile == nil {
		return postgres.SafeStatus{}, false
	}
	return store.postgresProfile.SafeStatus(), true
}
func (postgresDatabaseHealth) Readiness(store *IdentityStore) DatabaseReadiness {
	if store == nil || store.db == nil || store.postgresProfile == nil {
		return DatabaseReadiness{}
	}
	capability := store.postgresCapabilities
	stats := store.db.Stats()
	rlsStatus := store.WorkspaceRLSStatus(context.Background())
	result := DatabaseReadiness{
		SchemaExists: capability.SchemaExists, SchemaUsage: capability.SchemaUsage,
		ReadOnly: capability.ReadOnly || capability.InRecovery, TLSVerified: capability.TLS == store.postgresProfile.TLS,
		MigrationConnectionReady: !store.postgresProfile.MigrationConfigured || store.migratorCapabilities.Database != "",
		RLSEnabled:               rlsStatus.Enabled, RLSPolicyVersion: rlsStatus.PolicyVersion, RLSCoveredTables: len(rlsStatus.CoveredTables), RLSMissingTables: len(rlsStatus.MissingTables),
		ReadReady:           capability.SchemaExists && capability.SchemaUsage,
		WriteReady:          capability.SchemaExists && capability.SchemaUsage && !capability.ReadOnly && !capability.InRecovery,
		MigrationCompatible: store.migrationCompatible,
		PoolDegraded:        stats.MaxOpenConnections > 0 && stats.InUse >= stats.MaxOpenConnections,
	}
	switch {
	case !result.SchemaExists || !result.SchemaUsage:
		result.Failure = postgres.FailureSchemaIncompatible
	case result.ReadOnly:
		result.Failure = "read_only"
	case !result.TLSVerified:
		result.Failure = postgres.FailureTLS
	case !result.MigrationConnectionReady:
		result.Failure = postgres.FailureServerUnavailable
	case !result.MigrationCompatible:
		result.Failure = "migration_incompatible"
	case result.PoolDegraded:
		result.Failure = "pool_degraded"
	case store.postgresProfile.RLSEnabled && (!result.RLSEnabled || result.RLSMissingTables > 0):
		result.Failure = "rls_incompatible"
	default:
		result.Ready = true
	}
	return result
}

var databaseHealthFactories = map[string]func() databaseHealthProfile{
	"postgres": func() databaseHealthProfile { return postgresDatabaseHealth{} },
}

func databaseHealthFor(engine driver.Engine) databaseHealthProfile {
	if engine != nil {
		if factory := databaseHealthFactories[engine.Name()]; factory != nil {
			return factory()
		}
	}
	return portableDatabaseHealth{}
}
