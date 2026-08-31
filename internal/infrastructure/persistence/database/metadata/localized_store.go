package metadata

import (
	"context"
	"database/sql"
	"fmt"

	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	localizationmodel "github.com/domainry/domainry-identity/internal/domain/localization/model"

	"sort"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	"github.com/domainry/domainry-orm/query"
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

func firstNonEmptyLocalizedText(values ...string) string {
	for _, value := range values {
		if text := strings.TrimSpace(value); text != "" {
			return text
		}
	}
	return ""
}

func (s MetadataStore) syncManifestLocalizedTexts(ctx context.Context, tx *sql.Tx, manifest manifestmodel.ManifestSchema, now string) error {
	for _, seed := range manifestLocalizedTextSeeds(manifest, s.tenantWorkspaceID(ctx)) {
		if err := s.syncLocalizedText(ctx, tx, seed, now); err != nil {
			return err
		}
	}
	return nil
}

func (s MetadataStore) syncLocalizedText(ctx context.Context, tx *sql.Tx, seed metadatamodel.LocalizedText, now string) error {
	seed = normalizeLocalizedText(seed)
	if seed.EntityType == "" || seed.EntityKey == "" || seed.Property == "" || seed.Locale == "" || seed.Text == "" {
		return nil
	}
	queryValue, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer, "_identity_localized_texts", seed.WorkspaceID).
		Columns("text", "source_kind").
		Where(localizedTextIdentityPredicate(seed)).Build()
	if err != nil {
		return fmt.Errorf("build localized text read %s/%s/%s/%s: %w", seed.EntityType, seed.EntityKey, seed.Property, seed.Locale, err)
	}
	var currentText string
	var sourceKind string
	err = tx.QueryRowContext(ctx, queryValue, arguments...).Scan(&currentText, &sourceKind)
	if err == sql.ErrNoRows {
		statement, insertArguments, buildErr := localizedTextInsert(s, seed, now).Build()
		if buildErr != nil {
			return fmt.Errorf("build localized text insert %s/%s/%s/%s: %w", seed.EntityType, seed.EntityKey, seed.Property, seed.Locale, buildErr)
		}
		if _, err := tx.ExecContext(ctx, statement, insertArguments...); err != nil {
			return fmt.Errorf("insert localized text %s/%s/%s/%s: %w", seed.EntityType, seed.EntityKey, seed.Property, seed.Locale, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read localized text %s/%s/%s/%s: %w", seed.EntityType, seed.EntityKey, seed.Property, seed.Locale, err)
	}
	if strings.TrimSpace(sourceKind) != "generated" || currentText == seed.Text {
		return nil
	}
	update, updateArguments, buildErr := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer, "_identity_localized_texts", seed.WorkspaceID).
		Set("text", seed.Text).Set("source_id", seed.SourceID).Set("updated_at", now).
		Where(localizedTextIdentityPredicate(seed)).Build()
	if buildErr != nil {
		return fmt.Errorf("build localized text update %s/%s/%s/%s: %w", seed.EntityType, seed.EntityKey, seed.Property, seed.Locale, buildErr)
	}
	if _, err := tx.ExecContext(ctx, update, updateArguments...); err != nil {
		return fmt.Errorf("update localized text %s/%s/%s/%s: %w", seed.EntityType, seed.EntityKey, seed.Property, seed.Locale, err)
	}
	return nil
}

func (s MetadataStore) ListLocalizedTexts(ctx context.Context, workspaceID string, queryValue metadatamodel.LocalizedTextQuery) ([]metadatamodel.LocalizedText, error) {
	workspaceID, err := requireMetadataWorkspaceID(workspaceID, queryValue.WorkspaceID)
	if err != nil {
		return nil, err
	}
	queryValue.WorkspaceID = workspaceID
	predicates := []query.Predicate{}
	add := func(column string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		predicates = append(predicates, query.Equal(column, value))
	}
	add("entity_type", queryValue.EntityType)
	add("entity_key", queryValue.EntityKey)
	add("property", queryValue.Property)
	add("locale", queryValue.Locale)
	selectBuilder := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer, "_identity_localized_texts", workspaceID).
		Columns("workspace_id", "entity_type", "entity_key", "property", "locale", "text", "source_kind", "source_id", "created_at", "updated_at").
		OrderBy(query.Ascending("entity_type"), query.Ascending("entity_key"), query.Ascending("property"), query.Ascending("locale"))
	if len(predicates) > 0 {
		selectBuilder.Where(query.And(predicates...))
	}
	statement, arguments, err := selectBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("build localized text list: %w", err)
	}
	rows, err := s.database().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list localized texts: %w", err)
	}
	defer rows.Close()
	out := []metadatamodel.LocalizedText{}
	for rows.Next() {
		var item metadatamodel.LocalizedText
		if err := rows.Scan(&item.WorkspaceID, &item.EntityType, &item.EntityKey, &item.Property, &item.Locale, &item.Text, &item.SourceKind, &item.SourceID, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan localized text: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func localizedTextIdentityPredicate(text metadatamodel.LocalizedText) query.Predicate {
	return query.And(
		query.Equal("entity_type", text.EntityType),
		query.Equal("entity_key", text.EntityKey),
		query.Equal("property", text.Property),
		query.Equal("locale", text.Locale),
	)
}

func localizedTextInsert(store MetadataStore, text metadatamodel.LocalizedText, now string) *query.InsertBuilder {
	return query.NewWorkspaceInsertBuilder(store.store.SQLRenderer, "_identity_localized_texts", text.WorkspaceID).
		Columns("id", "entity_type", "entity_key", "property", "locale", "text", "source_kind", "source_id", "created_at", "updated_at").
		Values(localizedTextID(text), text.EntityType, text.EntityKey, text.Property, text.Locale, text.Text, text.SourceKind, text.SourceID, now, now)
}

func normalizeLocalizedText(text metadatamodel.LocalizedText) metadatamodel.LocalizedText {
	text.WorkspaceID = strings.TrimSpace(text.WorkspaceID)
	text.EntityType = strings.TrimSpace(text.EntityType)
	text.EntityKey = strings.TrimSpace(text.EntityKey)
	text.Property = strings.TrimSpace(text.Property)
	text.Locale = strings.TrimSpace(text.Locale)
	text.Text = strings.TrimSpace(text.Text)
	text.SourceKind = firstNonEmptyLocalizedText(text.SourceKind, "generated")
	text.SourceID = firstNonEmptyLocalizedText(text.SourceID, "generated-template")
	return text
}

func localizedTextID(text metadatamodel.LocalizedText) string {
	return strings.Join([]string{text.WorkspaceID, text.EntityType, text.EntityKey, text.Property, text.Locale}, ":")
}
