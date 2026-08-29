package connection

import (
	"context"
	"database/sql"

	"github.com/domainry/domainry-foundation/telemetry"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type PostgresProfile interface {
	Open(*telemetry.SQLMetrics) (*sql.DB, error)
	OpenMigration(*telemetry.SQLMetrics) (*sql.DB, error)
	ProbeWithBackoff(context.Context, *sql.DB) (postgres.Capabilities, error)
	ValidateRuntimeCapabilities(postgres.Capabilities, postgres.Capabilities) error
	Profile() *postgres.ConnectionProfile
}

type postgresProfileAdapter struct{ profile postgres.ConnectionProfile }

func (adapter postgresProfileAdapter) Open(metrics *telemetry.SQLMetrics) (*sql.DB, error) {
	return adapter.profile.Open(metrics)
}
func (adapter postgresProfileAdapter) OpenMigration(metrics *telemetry.SQLMetrics) (*sql.DB, error) {
	return adapter.profile.OpenMigration(metrics)
}
func (adapter postgresProfileAdapter) ProbeWithBackoff(ctx context.Context, db *sql.DB) (postgres.Capabilities, error) {
	return adapter.profile.ProbeWithBackoff(ctx, db)
}
func (adapter postgresProfileAdapter) ValidateRuntimeCapabilities(query, migrator postgres.Capabilities) error {
	return adapter.profile.ValidateRuntimeCapabilities(query, migrator)
}
func (adapter postgresProfileAdapter) Profile() *postgres.ConnectionProfile {
	profile := adapter.profile
	return &profile
}

type Dependencies struct {
	PostgresProfile func(config.Config) (PostgresProfile, error)
	ObservedSQL     func(string, string, string, *telemetry.SQLMetrics) (*sql.DB, error)
}

func DefaultDependencies() Dependencies {
	return Dependencies{
		PostgresProfile: func(cfg config.Config) (PostgresProfile, error) {
			profile, err := postgres.NewConnectionProfile(cfg)
			if err != nil {
				return nil, err
			}
			return postgresProfileAdapter{profile: profile}, nil
		},
		ObservedSQL: telemetry.OpenObservedSQL,
	}
}
