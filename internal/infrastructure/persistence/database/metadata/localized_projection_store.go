package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	metadatamodulehost "github.com/domainry/domainry-metadata-sdk/modulehost"
)

type metadataLocalizedProjection struct {
	Locale   string
	Property string
	Text     string
}

func (s MetadataStore) syncMetadataLocalizedTextTx(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string, payload []byte, sourceID, _ string) error {
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
	binding := s.store.Metadata()
	projectionBinding, ok := binding.(metadatasdk.LocalizationProjectionBinding)
	if !ok || projectionBinding.LocalizationProjection() == nil {
		return fmt.Errorf("Metadata localized-text projection is unavailable")
	}
	values := make([]metadatasdk.LocalizedText, 0, len(projections))
	for _, projection := range projections {
		values = append(values, metadatasdk.LocalizedText{Property: projection.Property, Locale: projection.Locale, Text: projection.Text})
	}
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		sourceID = "metadata_api"
	}
	return projectionBinding.LocalizationProjection().ReplaceResource(metadatamodulehost.WithExecutor(ctx, tx), metadatasdk.LocalizedTextResourceSnapshot{
		WorkspaceID: workspaceID, EntityType: entityType, EntityKey: entityKey,
		SourceKind: "metadata_definition", SourceID: sourceID, Values: values,
	})
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
