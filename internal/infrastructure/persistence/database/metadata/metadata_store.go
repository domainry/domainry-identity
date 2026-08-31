package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/query"
)

type MetadataStore struct {
	store       *database.IdentityStore
	db          *sql.DB
	workspaceID string
}

var _ metadatarepository.MetadataRepository = MetadataStore{}

func NewMetadataStore(store *database.IdentityStore, workspaceIDs ...string) MetadataStore {
	workspaceID := ""
	if len(workspaceIDs) > 0 {
		workspaceID = strings.TrimSpace(workspaceIDs[0])
	}
	return MetadataStore{store: store, db: store.DB(), workspaceID: workspaceID}
}

func (r MetadataStore) tenantWorkspaceID(ctx context.Context) string {
	if workspaceID := strings.TrimSpace(requestcontext.WorkspaceID(ctx)); workspaceID != "" {
		return workspaceID
	}
	return strings.TrimSpace(r.workspaceID)
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
	statement, arguments, err := query.NewSelectBuilder(r.store.SQLRenderer, "_identity_manifest_catalog").
		Columns("value").Where(query.Equal("key", "schema_hash")).Build()
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

func (r MetadataStore) MigrationPlan(ctx context.Context, scope identitymodel.SystemScope, _ manifestmodel.ManifestSchema) ([]metadatamodel.MetadataMigrationStep, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []metadatamodel.MetadataMigrationStep{}, nil
}

func (r MetadataStore) SyncManifest(ctx context.Context, scope identitymodel.SystemScope, _ manifestmodel.ManifestSchema) error {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return err
	}
	return ctx.Err()
}

func recordMutationTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelSerializable}
}
