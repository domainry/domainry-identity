package metadata

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func (r MetadataStore) refreshCatalogHashTx(ctx context.Context, tx *sql.Tx, now string) error {
	return r.refreshCatalogHashWithExecutorAt(ctx, tx, now)
}

func (r MetadataStore) refreshCatalogHashWithExecutor(
	ctx context.Context,
	executor database.ActionExecutionExecutor,
) error {
	return r.refreshCatalogHashWithExecutorAt(
		ctx,
		executor,
		time.Now().UTC().Format(time.RFC3339),
	)
}

func (r MetadataStore) refreshCatalogHashWithExecutorAt(
	ctx context.Context,
	executor database.ActionExecutionExecutor,
	now string,
) error {
	tables := metadataCatalogDefinitionTables()
	hash := sha256.New()
	for _, table := range tables {
		query, args, err := ormbuilder.NewSelectBuilder(r.store.SQLRenderer, table).
			Columns("resource_key", "schema_hash").OrderBy(ormbuilder.Ascending("resource_key")).Build()
		if err != nil {
			return err
		}
		rows, err := executor.QueryContext(ctx, query, args...)
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
	query, args, err := buildMetadataCatalogUpsert(r, "schema_hash", value, now)
	if err != nil {
		return err
	}
	_, err = executor.ExecContext(ctx, query, args...)
	return err
}

func (r MetadataStore) refreshCatalogHash(ctx context.Context) error {
	return r.refreshCatalogHashWithExecutor(ctx, r.database())
}

func metadataCatalogDefinitionTables() []string {
	return []string{"object_definitions", "field_definitions", "validation_definitions", "view_definitions", "action_definitions", "role_definitions", "identity_profile_binding_definitions"}
}
