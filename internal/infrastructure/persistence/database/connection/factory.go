package connection

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/domainry/domainry-foundation/telemetry"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type State struct {
	Database             *sql.DB
	MigrationDatabase    *sql.DB
	DSN                  string
	DatabaseSchema       string
	PostgresProfile      *postgres.ConnectionProfile
	PostgresCapabilities postgres.Capabilities
	MigratorCapabilities postgres.Capabilities
}

type strategy interface {
	Open(context.Context, config.Config, driver.Engine, Dependencies, *telemetry.SQLMetrics) (State, error)
}

type standardStrategy struct{}

func (standardStrategy) Open(_ context.Context, cfg config.Config, engine driver.Engine, dependencies Dependencies, metrics *telemetry.SQLMetrics) (State, error) {
	dsn, err := engine.DSN(cfg)
	if err != nil {
		return State{}, err
	}
	database, err := dependencies.ObservedSQL(engine.SQLDriver(), dsn, "identity", metrics)
	if err != nil {
		return State{}, err
	}
	return State{Database: database, DSN: dsn, DatabaseSchema: engine.DatabaseSchema(cfg)}, nil
}

type postgresStrategy struct{}

func (postgresStrategy) Open(ctx context.Context, cfg config.Config, _ driver.Engine, dependencies Dependencies, metrics *telemetry.SQLMetrics) (State, error) {
	connection, err := dependencies.PostgresProfile(cfg)
	if err != nil {
		return State{}, err
	}
	database, err := connection.Open(metrics)
	if err != nil {
		return State{}, err
	}
	state := State{Database: database, PostgresProfile: connection.Profile()}
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
			return State{}, err
		}
		if err := state.MigrationDatabase.PingContext(ctx); err != nil {
			closeState()
			return State{}, fmt.Errorf("connect postgres migration database (%s)", postgres.ClassifyConnectionFailure(err))
		}
	}
	state.PostgresCapabilities, err = connection.ProbeWithBackoff(ctx, database)
	if err != nil {
		closeState()
		return State{}, fmt.Errorf("probe postgres query connection (%s)", postgres.ClassifyConnectionFailure(err))
	}
	if state.MigrationDatabase != nil {
		state.MigratorCapabilities, err = connection.ProbeWithBackoff(ctx, state.MigrationDatabase)
		if err != nil {
			closeState()
			return State{}, fmt.Errorf("probe postgres migration connection (%s)", postgres.ClassifyConnectionFailure(err))
		}
	}
	if err := connection.ValidateRuntimeCapabilities(state.PostgresCapabilities, state.MigratorCapabilities); err != nil {
		closeState()
		return State{}, err
	}
	state.DatabaseSchema = state.PostgresProfile.Schema
	return state, nil
}

var strategies = map[string]strategy{
	"postgres": postgresStrategy{},
}

func Open(ctx context.Context, cfg config.Config, selected driver.Engine, dependencies Dependencies, metrics *telemetry.SQLMetrics) (State, error) {
	if strategy, found := strategies[selected.Name()]; found {
		return strategy.Open(ctx, cfg, selected, dependencies, metrics)
	}
	return standardStrategy{}.Open(ctx, cfg, selected, dependencies, metrics)
}
