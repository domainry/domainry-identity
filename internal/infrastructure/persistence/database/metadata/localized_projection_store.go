package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	"github.com/domainry/domainry-orm/query"
)

type metadataLocalizedProjection struct {
	Locale   string
	Property string
	Text     string
}

func (s MetadataStore) syncMetadataLocalizedTextTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string, payload []byte, sourceID, now string) error {
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		return fmt.Errorf("decode metadata localized text projection: %w", err)
	}
	rawI18n, declared := document["i18n"]
	if !declared {
		return nil
	}
	projections := metadataLocalizedProjections(rawI18n)
	workspaceID := s.tenantWorkspaceID(ctx)
	entityType, entityKey := strings.TrimSpace(resourceType), strings.TrimSpace(resourceKey)
	statement, arguments, err := query.NewWorkspaceDeleteBuilder(s.store.SQLRenderer, "_identity_localized_texts", workspaceID).
		Where(query.And(query.Equal("entity_type", entityType), query.Equal("entity_key", entityKey), query.Equal("source_kind", "metadata_definition"))).Build()
	if err != nil {
		return fmt.Errorf("build metadata localized text projection clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("clear metadata localized text projection: %w", err)
	}
	for _, projection := range projections {
		localized := metadatamodel.LocalizedText{WorkspaceID: workspaceID, EntityType: entityType, EntityKey: entityKey, Property: projection.Property, Locale: projection.Locale, Text: projection.Text}
		insert := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer, "_identity_localized_texts", workspaceID).
			Columns("id", "entity_type", "entity_key", "property", "locale", "text", "source_kind", "source_id", "created_at", "updated_at").
			Values(localizedTextID(localized), entityType, entityKey, projection.Property, projection.Locale, projection.Text, "metadata_definition", sourceID, now, now)
		s.store.Engine.ApplyUpsert(insert, []string{"workspace_id", "entity_type", "entity_key", "property", "locale"}, "text", "source_kind", "source_id", "updated_at")
		statement, arguments, err = insert.Build()
		if err != nil {
			return fmt.Errorf("build metadata localized text projection upsert: %w", err)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return fmt.Errorf("insert metadata localized text projection: %w", err)
		}
	}
	return nil
}

func metadataLocalizedProjections(value any) []metadataLocalizedProjection {
	locales, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := []metadataLocalizedProjection{}
	for locale, rawProperties := range locales {
		properties, ok := rawProperties.(map[string]any)
		if !ok {
			continue
		}
		for property, rawText := range properties {
			text, ok := rawText.(string)
			if !ok || strings.TrimSpace(locale) == "" || strings.TrimSpace(property) == "" || strings.TrimSpace(text) == "" {
				continue
			}
			result = append(result, metadataLocalizedProjection{Locale: strings.TrimSpace(locale), Property: strings.TrimSpace(property), Text: text})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Locale+"\x00"+result[i].Property < result[j].Locale+"\x00"+result[j].Property
	})
	return result
}
