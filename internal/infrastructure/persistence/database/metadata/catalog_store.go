package metadata

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-orm/query"
)

type metadataSQLDialect interface {
	Identifier(string) string
	TableIdentifier(string) string
	Placeholder(int) string
}

func (s MetadataStore) manifestMetadataSeeded(ctx context.Context) (bool, error) {
	queryValue, args, err := query.NewSelectBuilder(s.store.SQLRenderer, "_identity_manifest_catalog").
		Projections(query.Project(query.CountAll())).Where(query.Equal("key", "template_id")).Build()
	if err != nil {
		return false, fmt.Errorf("build metadata catalog seed query: %w", err)
	}
	var count int
	if err := s.database().QueryRowContext(ctx, queryValue, args...).Scan(&count); err != nil {
		return false, fmt.Errorf("read metadata catalog: %w", err)
	}
	return count > 0, nil
}

func (s MetadataStore) ManifestIdentitySeedSyncedVersion(ctx context.Context) (string, error) {
	queryValue, args, buildErr := query.NewSelectBuilder(s.store.SQLRenderer, "_identity_manifest_catalog").
		Columns("value").Where(query.Equal("key", "identity_seed_synced_version")).Build()
	if buildErr != nil {
		return "", fmt.Errorf("build identity seed version query: %w", buildErr)
	}
	var value string
	if err := s.database().QueryRowContext(ctx, queryValue, args...).Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("read identity seed synced version: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func (s MetadataStore) SetManifestIdentitySeedSyncedVersion(ctx context.Context, version string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	queryValue, args, err := buildMetadataCatalogUpsert(s, "identity_seed_synced_version", strings.TrimSpace(version), now)
	if err != nil {
		return fmt.Errorf("build identity seed version upsert: %w", err)
	}
	if _, err := s.database().ExecContext(ctx, queryValue, args...); err != nil {
		return fmt.Errorf("set identity seed synced version: %w", err)
	}
	return nil
}

func (s MetadataStore) ManifestOrganizationScopeSeedState(ctx context.Context) (string, error) {
	queryValue, args, buildErr := query.NewSelectBuilder(s.store.SQLRenderer, "_identity_manifest_catalog").
		Columns("value").Where(query.Equal("key", "organization_scope_seed_state")).Build()
	if buildErr != nil {
		return "", fmt.Errorf("build organization scope seed query: %w", buildErr)
	}
	var value string
	if err := s.database().QueryRowContext(ctx, queryValue, args...).Scan(&value); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("read organization scope seed state: %w", err)
	}
	return strings.TrimSpace(value), nil
}

func (s MetadataStore) SetManifestOrganizationScopeSeedState(ctx context.Context, state string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	queryValue, args, err := buildMetadataCatalogUpsert(s, "organization_scope_seed_state", strings.TrimSpace(state), now)
	if err != nil {
		return fmt.Errorf("build organization scope seed upsert: %w", err)
	}
	if _, err := s.database().ExecContext(ctx, queryValue, args...); err != nil {
		return fmt.Errorf("set organization scope seed state: %w", err)
	}
	return nil
}

func buildMetadataCatalogUpsert(store MetadataStore, key, value, now string) (string, []any, error) {
	insert := query.NewInsertBuilder(store.store.SQLRenderer, "_identity_manifest_catalog").
		Columns("key", "value", "updated_at").Values(key, value, now)
	return store.store.Engine.ApplyUpsert(insert, []string{"key"}, "value", "updated_at").Build()
}

func (s MetadataStore) insertMetadataCatalog(ctx context.Context, tx *sql.Tx, key string, value string, now string) error {
	queryValue, args, err := query.NewInsertBuilder(s.store.SQLRenderer, "_identity_manifest_catalog").
		Columns("key", "value", "updated_at").Values(strings.TrimSpace(key), strings.TrimSpace(value), now).Build()
	if err != nil {
		return fmt.Errorf("build metadata catalog insert %s: %w", key, err)
	}
	if _, err := tx.ExecContext(ctx, queryValue, args...); err != nil {
		return fmt.Errorf("insert metadata catalog %s: %w", key, err)
	}
	return nil
}

func (s MetadataStore) upsertMetadataCatalog(ctx context.Context, tx *sql.Tx, key string, value string, now string) error {
	updateQuery, args, buildErr := query.NewUpdateBuilder(s.store.SQLRenderer, "_identity_manifest_catalog").
		Set("value", strings.TrimSpace(value)).Set("updated_at", now).Where(query.Equal("key", strings.TrimSpace(key))).Build()
	if buildErr != nil {
		return fmt.Errorf("build metadata catalog update %s: %w", key, buildErr)
	}
	result, err := tx.ExecContext(ctx, updateQuery, args...)
	if err != nil {
		return fmt.Errorf("update metadata catalog %s: %w", key, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read updated metadata catalog rows %s: %w", key, err)
	}
	if rows > 0 {
		return nil
	}
	return s.insertMetadataCatalog(ctx, tx, key, value, now)
}

func (s MetadataStore) refreshMetadataCatalogHash(ctx context.Context) error {
	return s.refreshCatalogHash(ctx)
}
