package database

import (
	"context"
	"database/sql"

	"github.com/domainry/domainry-foundation/secrets"
	"github.com/domainry/domainry-foundation/telemetry"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

type identityPostgresProfile interface {
	Open(*telemetry.SQLMetrics) (*sql.DB, error)
	OpenMigration(*telemetry.SQLMetrics) (*sql.DB, error)
	ProbeWithBackoff(context.Context, *sql.DB) (postgres.Capabilities, error)
	ValidateRuntimeCapabilities(postgres.Capabilities, postgres.Capabilities) error
	Profile() *postgres.ConnectionProfile
}

type identityPostgresProfileAdapter struct{ profile postgres.ConnectionProfile }

func (adapter identityPostgresProfileAdapter) Open(metrics *telemetry.SQLMetrics) (*sql.DB, error) {
	return adapter.profile.Open(metrics)
}
func (adapter identityPostgresProfileAdapter) OpenMigration(metrics *telemetry.SQLMetrics) (*sql.DB, error) {
	return adapter.profile.OpenMigration(metrics)
}
func (adapter identityPostgresProfileAdapter) ProbeWithBackoff(ctx context.Context, db *sql.DB) (postgres.Capabilities, error) {
	return adapter.profile.ProbeWithBackoff(ctx, db)
}
func (adapter identityPostgresProfileAdapter) ValidateRuntimeCapabilities(query, migrator postgres.Capabilities) error {
	return adapter.profile.ValidateRuntimeCapabilities(query, migrator)
}
func (adapter identityPostgresProfileAdapter) Profile() *postgres.ConnectionProfile {
	profile := adapter.profile
	return &profile
}

type identityOpenDependencies struct {
	dialect         func(string) (dialect, error)
	postgresProfile func(config.Config) (identityPostgresProfile, error)
	observedSQL     func(string, string, string, *telemetry.SQLMetrics) (*sql.DB, error)
	keyRing         func(secrets.Key, ...secrets.Key) (secrets.KeyProvider, error)
}

func defaultIdentityOpenDependencies() identityOpenDependencies {
	return identityOpenDependencies{
		dialect: engineFor,
		postgresProfile: func(cfg config.Config) (identityPostgresProfile, error) {
			profile, err := postgres.NewConnectionProfile(cfg)
			if err != nil {
				return nil, err
			}
			return identityPostgresProfileAdapter{profile: profile}, nil
		},
		observedSQL: telemetry.OpenObservedSQL,
		keyRing: func(active secrets.Key, decryptOnly ...secrets.Key) (secrets.KeyProvider, error) {
			return secrets.NewMemoryKeyRing(active, decryptOnly...)
		},
	}
}
