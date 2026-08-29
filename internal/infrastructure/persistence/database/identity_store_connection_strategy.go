package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/domainry/domainry-foundation/telemetry"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type identityConnectionState struct {
	Database             *sql.DB
	MigrationDatabase    *sql.DB
	DSN                  string
	DatabaseSchema       string
	PostgresProfile      *postgres.ConnectionProfile
	PostgresCapabilities postgres.Capabilities
	MigratorCapabilities postgres.Capabilities
}

type identityConnectionStrategy interface {
	Open(context.Context, config.Config, dialect, identityOpenDependencies, *telemetry.SQLMetrics) (identityConnectionState, error)
}

type standardIdentityConnectionStrategy struct{}

func (standardIdentityConnectionStrategy) Open(_ context.Context, cfg config.Config, dialect dialect, dependencies identityOpenDependencies, metrics *telemetry.SQLMetrics) (identityConnectionState, error) {
	dsn, err := dialect.DSN(cfg)
	if err != nil {
		return identityConnectionState{}, err
	}
	database, err := dependencies.observedSQL(dialect.SQLDriver(), dsn, "identity", metrics)
	if err != nil {
		return identityConnectionState{}, err
	}
	return identityConnectionState{Database: database, DSN: dsn, DatabaseSchema: dialect.DatabaseSchema(cfg)}, nil
}

type postgresIdentityConnectionStrategy struct{}

func (postgresIdentityConnectionStrategy) Open(ctx context.Context, cfg config.Config, _ dialect, dependencies identityOpenDependencies, metrics *telemetry.SQLMetrics) (identityConnectionState, error) {
	connection, err := dependencies.postgresProfile(cfg)
	if err != nil {
		return identityConnectionState{}, err
	}
	database, err := connection.Open(metrics)
	if err != nil {
		return identityConnectionState{}, err
	}
	state := identityConnectionState{Database: database, PostgresProfile: connection.Profile()}
	closeState := func() {
		if state.MigrationDatabase != nil {
			_ = state.MigrationDatabase.Close()
		}
		_ = state.Database.Close()
	}
	if state.PostgresProfile.MigrationConfigured {
		state.MigrationDatabase, err = connection.OpenMigration(metrics)
		if err != nil {
			closeState()
			return identityConnectionState{}, err
		}
		if err := state.MigrationDatabase.PingContext(ctx); err != nil {
			closeState()
			return identityConnectionState{}, fmt.Errorf("connect postgres migration database (%s)", postgres.ClassifyConnectionFailure(err))
		}
	}
	state.PostgresCapabilities, err = connection.ProbeWithBackoff(ctx, database)
	if err != nil {
		closeState()
		return identityConnectionState{}, fmt.Errorf("probe postgres query connection (%s)", postgres.ClassifyConnectionFailure(err))
	}
	if state.MigrationDatabase != nil {
		state.MigratorCapabilities, err = connection.ProbeWithBackoff(ctx, state.MigrationDatabase)
		if err != nil {
			closeState()
			return identityConnectionState{}, fmt.Errorf("probe postgres migration connection (%s)", postgres.ClassifyConnectionFailure(err))
		}
	}
	if err := connection.ValidateRuntimeCapabilities(state.PostgresCapabilities, state.MigratorCapabilities); err != nil {
		closeState()
		return identityConnectionState{}, err
	}
	state.DatabaseSchema = state.PostgresProfile.Schema
	return state, nil
}

var identityConnectionStrategies = map[string]identityConnectionStrategy{
	"postgres": postgresIdentityConnectionStrategy{},
}

func identityConnectionStrategyFor(selected dialect) identityConnectionStrategy {
	if strategy, found := identityConnectionStrategies[selected.Name()]; found {
		return strategy
	}
	return standardIdentityConnectionStrategy{}
}
