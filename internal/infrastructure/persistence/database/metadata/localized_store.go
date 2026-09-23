package metadata

import (
	"context"
	"fmt"

	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"

	"sort"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatasdk "github.com/domainry/domainry-metadata-sdk"
)

func manifestLocalizedTextSeeds(seed manifestmodel.ManifestSchema, workspaceID string) []metadatamodel.LocalizedText {
	sourceID := strings.TrimSpace(seed.TemplateID)
	if sourceID == "" {
		sourceID = "generated-template"
	}
	defaultLocale := manifestDefaultLocale(seed)
	out := []metadatamodel.LocalizedText{}
	addDefault := func(entityType string, entityKey string, property string, text string) {
		entityType = strings.TrimSpace(entityType)
		entityKey = strings.TrimSpace(entityKey)
		property = strings.TrimSpace(property)
		text = strings.TrimSpace(text)
		if entityKey == "" || text == "" {
			return
		}
		out = append(out, metadatamodel.LocalizedText{
			WorkspaceID: workspaceID,
			EntityType:  entityType,
			EntityKey:   entityKey,
			Property:    property,
			Locale:      defaultLocale,
			Text:        text,
			SourceKind:  "generated",
			SourceID:    sourceID,
		})
	}
	addI18n := func(entityType string, entityKey string, values localizationmodel.LocalizedTextMap) {
		entityType = strings.TrimSpace(entityType)
		entityKey = strings.TrimSpace(entityKey)
		if entityKey == "" || len(values) == 0 {
			return
		}
		for locale, properties := range values {
			locale = strings.TrimSpace(locale)
			if locale == "" {
				continue
			}
			for property, text := range properties {
				property = strings.TrimSpace(property)
				text = strings.TrimSpace(text)
				if property == "" || text == "" {
					continue
				}
				out = append(out, metadatamodel.LocalizedText{
					WorkspaceID: workspaceID,
					EntityType:  entityType,
					EntityKey:   entityKey,
					Property:    property,
					Locale:      locale,
					Text:        text,
					SourceKind:  "generated",
					SourceID:    sourceID,
				})
			}
		}
	}
	addDefault("app", "app", "name", seed.Name)
	addDefault("app", "app", "description", seed.Description)
	addI18n("app", "app", seed.I18n)
	for _, object := range seed.Objects {
		addDefault("object", object.Key, "name", object.Name)
		addDefault("object", object.Key, "description", object.Description)
		addI18n("object", object.Key, object.I18n)
		for _, field := range object.Fields {
			fieldKey := metadataJoinedKey(object.Key, field.Key)
			addDefault("field", fieldKey, "name", field.Name)
			addI18n("field", fieldKey, field.I18n)
			addValueOptionDefaultTexts(&out, "field_option", fieldKey, field.Options, defaultLocale, sourceID, workspaceID)
			addValueOptionI18n(&out, "field_option", fieldKey, field.Options, sourceID, workspaceID)
		}
		for index, validation := range object.Validations {
			key := validation.Key
			if strings.TrimSpace(key) == "" {
				key = validationMetadataKey(object.Key, index, validation)
			}
			addDefault("validation", key, "message", validation.Message)
			addI18n("validation", key, validation.I18n)
		}
	}
	for _, action := range seed.Actions {
		addDefault("action", action.Key, "label", action.Label)
		addI18n("action", action.Key, action.I18n)
		for _, field := range action.PayloadFields {
			addDefault("action_payload_field", metadataJoinedKey(action.Key, field.Key), "name", field.Name)
			addI18n("action_payload_field", metadataJoinedKey(action.Key, field.Key), field.I18n)
		}
	}
	for _, role := range seed.Roles {
		addDefault("role", role.Key, "name", role.Name)
		addI18n("role", role.Key, role.I18n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		for _, less := range []int{
			strings.Compare(out[i].EntityType, out[j].EntityType),
			strings.Compare(out[i].EntityKey, out[j].EntityKey),
			strings.Compare(out[i].Property, out[j].Property),
			strings.Compare(out[i].Locale, out[j].Locale),
		} {
			if less < 0 {
				return true
			}
			if less > 0 {
				return false
			}
		}
		return false
	})
	return out
}

func manifestDefaultLocale(seed manifestmodel.ManifestSchema) string {
	if locale := strings.TrimSpace(seed.DefaultLocale); locale != "" {
		return locale
	}
	return "en-US"
}

func addValueOptionI18n(out *[]metadatamodel.LocalizedText, entityType string, parentKey string, value any, sourceID, workspaceID string) {
	for _, option := range localizedValueOptionMaps(value) {
		key := strings.TrimSpace(fmt.Sprint(option["value"]))
		if key == "" || key == "<nil>" {
			key = strings.TrimSpace(fmt.Sprint(option["key"]))
		}
		i18n, ok := option["i18n"].(map[string]any)
		if !ok || key == "" || key == "<nil>" {
			continue
		}
		for locale, propertiesAny := range i18n {
			properties, ok := propertiesAny.(map[string]any)
			if !ok {
				continue
			}
			for property, textAny := range properties {
				text := strings.TrimSpace(fmt.Sprint(textAny))
				if strings.TrimSpace(locale) == "" || strings.TrimSpace(property) == "" || text == "" || text == "<nil>" {
					continue
				}
				*out = append(*out, metadatamodel.LocalizedText{
					WorkspaceID: workspaceID,
					EntityType:  entityType,
					EntityKey:   metadataJoinedKey(parentKey, key),
					Property:    strings.TrimSpace(property),
					Locale:      strings.TrimSpace(locale),
					Text:        text,
					SourceKind:  "generated",
					SourceID:    sourceID,
				})
			}
		}
	}
}

func addValueOptionDefaultTexts(out *[]metadatamodel.LocalizedText, entityType string, parentKey string, value any, locale string, sourceID, workspaceID string) {
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return
	}
	for _, option := range localizedValueOptionMaps(value) {
		key := strings.TrimSpace(fmt.Sprint(option["value"]))
		if key == "" || key == "<nil>" {
			key = strings.TrimSpace(fmt.Sprint(option["key"]))
		}
		if key == "" || key == "<nil>" {
			continue
		}
		for _, property := range []string{"label", "description"} {
			text := strings.TrimSpace(fmt.Sprint(option[property]))
			if text == "" || text == "<nil>" {
				continue
			}
			*out = append(*out, metadatamodel.LocalizedText{
				WorkspaceID: workspaceID,
				EntityType:  entityType,
				EntityKey:   metadataJoinedKey(parentKey, key),
				Property:    property,
				Locale:      locale,
				Text:        text,
				SourceKind:  "generated",
				SourceID:    sourceID,
			})
		}
	}
}

func localizedValueOptionMaps(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return append([]map[string]any(nil), typed...)
	case []any:
		out := []map[string]any{}
		for _, item := range typed {
			if option, ok := item.(map[string]any); ok {
				out = append(out, option)
			}
		}
		return out
	default:
		return nil
	}
}

func (s MetadataStore) ListLocalizedTexts(ctx context.Context, workspaceID string, queryValue metadatamodel.LocalizedTextQuery) ([]metadatamodel.LocalizedText, error) {
	workspaceID, err := requireMetadataWorkspaceID(workspaceID, queryValue.WorkspaceID)
	if err != nil {
		return nil, err
	}
	binding := s.store.Metadata()
	if binding == nil || binding.Localization() == nil {
		return nil, fmt.Errorf("Metadata localization is unavailable")
	}
	values, err := binding.Localization().List(ctx, metadatasdk.LocalizedTextQuery{
		WorkspaceID: workspaceID, EntityType: queryValue.EntityType, EntityKey: queryValue.EntityKey,
		Property: queryValue.Property, Locale: queryValue.Locale,
	})
	if err != nil {
		return nil, fmt.Errorf("list Metadata localized texts: %w", err)
	}
	out := make([]metadatamodel.LocalizedText, 0, len(values))
	for _, item := range values {
		out = append(out, metadatamodel.LocalizedText{
			WorkspaceID: item.WorkspaceID, EntityType: item.EntityType, EntityKey: item.EntityKey,
			Property: item.Property, Locale: item.Locale, Text: item.Text,
			SourceKind: item.SourceKind, SourceID: item.SourceID, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
		})
	}
	return out, nil
}
