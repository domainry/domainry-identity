package metadata

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	metadatamodulehost "github.com/domainry/domainry-metadata-sdk/modulehost"
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
	hash := sha256.New()
	binding := r.store.Metadata()
	if binding == nil || binding.Definitions() == nil {
		return fmt.Errorf("Metadata definitions are unavailable")
	}
	snapshot, err := binding.Definitions().Snapshot(metadatamodulehost.WithExecutor(ctx, executor), metadatasdk.DefinitionQuery{CrossOwner: true})
	if err != nil {
		return err
	}
	hash.Write([]byte("metadata:"))
	for _, definition := range snapshot.Definitions {
		hash.Write([]byte(definition.Owner + ":" + definition.ResourceType + ":" + definition.ResourceKey + ":" + definition.SchemaHash + "|"))
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
