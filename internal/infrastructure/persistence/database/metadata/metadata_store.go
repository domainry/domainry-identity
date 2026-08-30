// Package metadata persists Identity authorization metadata. It never creates
// or migrates host business-record tables.
package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type MetadataStore struct {
	store *database.IdentityStore
	db    *sql.DB
}

var _ metadatarepository.MetadataRepository = MetadataStore{}

func NewMetadataStore(store *database.IdentityStore) MetadataStore {
	return MetadataStore{store: store, db: store.DB()}
}

func (r MetadataStore) database() *sql.DB {
	if r.db != nil {
		return r.db
	}
	return r.store.DB()
}

func (r MetadataStore) SnapshotRevision(ctx context.Context, scope identitymodel.SystemScope) (string, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return "", err
	}
	executor := transaction.Executor(r.database())
	if actionExecutor := transaction.ExecutorFromContext(ctx); actionExecutor != nil {
		executor = actionExecutor
	}
	var revision string
	statement, arguments, err := ormbuilder.NewSelectBuilder(r.store.SQLRenderer, "application_schema_catalog").
		Columns("value").Where(ormbuilder.Equal("key", "schema_hash")).Build()
	if err != nil {
		return "", fmt.Errorf("build metadata snapshot revision read: %w", err)
	}
	err = executor.QueryRowContext(ctx, statement, arguments...).Scan(&revision)
	if err == sql.ErrNoRows {
		if refreshErr := r.refreshCatalogHashWithExecutor(ctx, executor); refreshErr != nil {
			return "", refreshErr
		}
		err = executor.QueryRowContext(ctx, statement, arguments...).Scan(&revision)
	}
	if err != nil {
		return "", fmt.Errorf("load metadata snapshot revision: %w", err)
	}
	return strings.TrimSpace(revision), nil
}

// MigrationPlan is intentionally empty. Identity publishes object and field
// definitions for authorization, while the integrating host owns physical
// business storage and its migrations.
func (r MetadataStore) MigrationPlan(ctx context.Context, scope identitymodel.SystemScope, _ manifestmodel.ManifestSchema) ([]metadatamodel.MetadataMigrationStep, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []metadatamodel.MetadataMigrationStep{}, nil
}

// SyncManifest validates the call boundary only; definition persistence is
// handled by the metadata catalog and publication repositories.
func (r MetadataStore) SyncManifest(ctx context.Context, scope identitymodel.SystemScope, _ manifestmodel.ManifestSchema) error {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return err
	}
	return ctx.Err()
}

func recordMutationTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelSerializable}
}
