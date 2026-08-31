package metadata

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	metadatarepository "github.com/domainry/domainry-metadata-sdk/repository"
	"github.com/domainry/domainry-orm/query"
)

func (r MetadataStore) refreshCatalogHashTx(ctx context.Context, tx *sql.Tx, now string) error {
	return r.refreshCatalogHashWithExecutorAt(ctx, tx, now)
}

func (r MetadataStore) refreshCatalogHashWithExecutor(
	ctx context.Context,
	executor transaction.Executor,
) error {
	return r.refreshCatalogHashWithExecutorAt(
		ctx,
		executor,
		time.Now().UTC().Format(time.RFC3339),
	)
}

func (r MetadataStore) refreshCatalogHashWithExecutorAt(
	ctx context.Context,
	executor transaction.Executor,
	now string,
) error {
	tables := metadataCatalogDefinitionTables()
	hash := sha256.New()
	definitions := r.store.MetadataDefinitions()
	executorRepository, ok := definitions.(metadatarepository.ExecutorSnapshotRepository)
	if !ok {
		return fmt.Errorf("Metadata executor snapshot repository is unavailable")
	}
	snapshot, err := executorRepository.DefinitionSnapshotWithExecutor(ctx, executor)
	if err != nil {
		return err
	}
	hash.Write([]byte("metadata:"))
	for _, definition := range snapshot.Definitions {
		hash.Write([]byte(definition.ResourceType + ":" + definition.Key + ":" + definition.SchemaHash + "|"))
	}
	for _, table := range tables {
		queryValue, args, err := query.NewSelectBuilder(r.store.SQLRenderer, table).
			Columns("resource_key", "schema_hash").OrderBy(query.Ascending("resource_key")).Build()
		if err != nil {
			return err
		}
		rows, err := executor.QueryContext(ctx, queryValue, args...)
		if err != nil {
			return err
		}
		hash.Write([]byte(table + ":"))
		for rows.Next() {
			var key, schemaHash string
			if err := rows.Scan(&key, &schemaHash); err != nil {
				rows.Close()
				return err
			}
			hash.Write([]byte(key + ":" + schemaHash + "|"))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	value := hex.EncodeToString(hash.Sum(nil))
	queryValue, args, err := buildMetadataCatalogUpsert(r, "schema_hash", value, now)
	if err != nil {
		return err
	}
	_, err = executor.ExecContext(ctx, queryValue, args...)
	return err
}

func (r MetadataStore) refreshCatalogHash(ctx context.Context) error {
	return r.refreshCatalogHashWithExecutor(ctx, r.database())
}

func metadataCatalogDefinitionTables() []string {
	return []string{"_metadata_role_definitions", "_identity_profile_binding_definitions"}
}
