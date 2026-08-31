package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodulehost "github.com/domainry/domainry-metadata-sdk/modulehost"
	"github.com/domainry/domainry-orm/query"
)

var closeGeneratedActionRows = func(rows *sql.Rows) error { return rows.Close() }

type metadataResourceSeed struct {
	ResourceType  string
	Table         string
	Key           string
	ObjectKey     string
	Name          string
	SchemaVersion string
	SourceKind    string
	SourceID      string
	Payload       any
}

func (s MetadataStore) EnsureManifestMetadata(ctx context.Context, seed manifestmodel.ManifestSchema) error {
	ctx = s.manifestMetadataContext(ctx)
	seeded, err := s.manifestMetadataSeeded(ctx)
	if err != nil {
		return err
	}
	if seeded {
		return s.SyncManifestMetadata(ctx, seed)
	}
	seeds, err := manifestMetadataSeeds(seed)
	if err != nil {
		return err
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin metadata seed: %w", err)
	}
	defer tx.Rollback()
	ctx = metadatamodulehost.WithExecutor(ctx, tx)
	if err := s.syncBusinessMetadataDefinitions(ctx, seed); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for key, value := range map[string]string{
		"template_id":      seed.TemplateID,
		"template_version": seed.Version,
		"default_locale":   manifestDefaultLocale(seed),
		"name":             seed.Name,
		"schema_version":   seed.Version,
	} {
		if err := s.insertMetadataCatalog(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for _, seed := range seeds {
		if err := s.insertMetadataResource(ctx, tx, seed, now); err != nil {
			return err
		}
	}
	if err := s.syncManifestLocalizedTexts(ctx, tx, seed, now); err != nil {
		return err
	}
	if err := s.refreshCatalogHashWithExecutorAt(ctx, tx, now); err != nil {
		return fmt.Errorf("refresh Identity metadata catalog: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit metadata seed: %w", err)
	}
	return nil
}

func (s MetadataStore) SyncManifestMetadata(ctx context.Context, seed manifestmodel.ManifestSchema) error {
	ctx = s.manifestMetadataContext(ctx)
	seeds, err := manifestMetadataSeeds(seed)
	if err != nil {
		return err
	}
	tx, err := s.database().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin metadata sync: %w", err)
	}
	defer tx.Rollback()
	ctx = metadatamodulehost.WithExecutor(ctx, tx)
	if err := s.syncBusinessMetadataDefinitions(ctx, seed); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for key, value := range map[string]string{
		"template_id":      seed.TemplateID,
		"template_version": seed.Version,
		"default_locale":   manifestDefaultLocale(seed),
		"name":             seed.Name,
		"schema_version":   seed.Version,
	} {
		if err := s.upsertMetadataCatalog(ctx, tx, key, value, now); err != nil {
			return err
		}
	}
	for _, seed := range seeds {
		if err := s.syncMetadataResource(ctx, tx, seed, now); err != nil {
			return err
		}
	}
	if err := s.syncManifestLocalizedTexts(ctx, tx, seed, now); err != nil {
		return err
	}
	if err := s.refreshCatalogHashWithExecutorAt(ctx, tx, now); err != nil {
		return fmt.Errorf("refresh Identity metadata catalog: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit metadata sync: %w", err)
	}
	return nil
}

func (s MetadataStore) manifestMetadataContext(ctx context.Context) context.Context {
	if requestcontext.WorkspaceID(ctx) != "" {
		return ctx
	}
	return requestcontext.WithWorkspaceID(ctx, s.tenantWorkspaceID(ctx))
}

func manifestGeneratedSourceID(manifest manifestmodel.ManifestSchema) string {
	if sourceID := strings.TrimSpace(manifest.TemplateID); sourceID != "" {
		return sourceID
	}
	return "generated-template"
}

func (s MetadataStore) disableRemovedGeneratedDefinitions(ctx context.Context, tx *sql.Tx, table, sourceID string, activeKeys map[string]bool, now string) error {
	queryValue, arguments, err := query.NewSelectBuilder(s.store.SQLRenderer, table).
		Columns("resource_key").
		Where(query.And(query.Equal("source_kind", "generated"), query.Equal("source_id", sourceID), query.IsNull("disabled_at"))).Build()
	if err != nil {
		return fmt.Errorf("build generated %s manifest sync list: %w", table, err)
	}
	rows, err := tx.QueryContext(ctx, queryValue, arguments...)
	if err != nil {
		return fmt.Errorf("list generated %s for manifest sync: %w", table, err)
	}
	removedKeys := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return fmt.Errorf("scan generated %s for manifest sync: %w", table, err)
		}
		if !activeKeys[key] {
			removedKeys = append(removedKeys, key)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read generated %s for manifest sync: %w", table, err)
	}
	if err := closeGeneratedActionRows(rows); err != nil {
		return fmt.Errorf("close generated %s for manifest sync: %w", table, err)
	}
	if len(removedKeys) == 0 {
		return nil
	}
	update, updateArguments, err := query.NewUpdateBuilder(s.store.SQLRenderer, table).
		Set("disabled_at", now).Set("updated_at", now).
		Where(query.In("resource_key", stringValues(removedKeys)...)).Build()
	if err != nil {
		return fmt.Errorf("build removed generated %s disable: %w", table, err)
	}
	if _, err := tx.ExecContext(ctx, update, updateArguments...); err != nil {
		return fmt.Errorf("disable removed generated %s entries: %w", table, err)
	}
	return nil
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
