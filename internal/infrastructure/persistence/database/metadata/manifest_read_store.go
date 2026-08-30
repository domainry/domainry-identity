package metadata

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

// MetadataStore is the request-aware storage boundary for metadata.
// Compatibility methods on Store remain available while callers migrate.
func (r MetadataStore) LoadManifest(ctx context.Context, scope identitymodel.SystemScope) (manifestmodel.ManifestSchema, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	catalog, err := r.loadCatalog(ctx)
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	objects, fields, validations, actions, err := r.loadBusinessDefinitions(ctx)
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	roles, err := loadMetadataSliceContext[identitymodel.RoleSchema](ctx, r.database(), r.store, "_metadata_role_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	profileBindings, err := loadMetadataSliceContext[identitymodel.IdentityProfileExtension](ctx, r.database(), r.store, "_identity_profile_binding_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	fieldsByObject := map[string][]definitionmodel.FieldSchema{}
	for _, field := range fields {
		fieldsByObject[metadataFieldObjectKey(field)] = append(fieldsByObject[metadataFieldObjectKey(field)], field)
	}
	validationsByObject := map[string][]definitionmodel.ValidationSchema{}
	for _, validation := range validations {
		validationsByObject[validation.ObjectKey] = append(validationsByObject[validation.ObjectKey], validation)
	}
	for index := range objects {
		objects[index].Fields = append([]definitionmodel.FieldSchema(nil), fieldsByObject[objects[index].Key]...)
		objects[index].Validations = append([]definitionmodel.ValidationSchema(nil), validationsByObject[objects[index].Key]...)
	}
	return manifestmodel.ManifestSchema{
		TemplateID: catalog["template_id"], Version: catalog["template_version"], DefaultLocale: catalog["default_locale"], Name: catalog["name"],
		Objects: objects, Actions: actions, Roles: roles, IdentityProfileExtensions: profileBindings,
	}, nil
}

func (r MetadataStore) loadBusinessDefinitions(ctx context.Context) ([]definitionmodel.ObjectSchema, []definitionmodel.FieldSchema, []definitionmodel.ValidationSchema, []definitionmodel.ActionSchema, error) {
	repository := r.store.MetadataDefinitions()
	if repository == nil {
		return nil, nil, nil, nil, fmt.Errorf("Metadata definition repository is unavailable")
	}
	snapshot, err := repository.DefinitionSnapshot(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	objects, fields := []definitionmodel.ObjectSchema{}, []definitionmodel.FieldSchema{}
	validations, actions := []definitionmodel.ValidationSchema{}, []definitionmodel.ActionSchema{}
	for _, definition := range snapshot.Definitions {
		switch definition.ResourceType {
		case "object":
			var value definitionmodel.ObjectSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode object definition %s: %w", definition.Key, err)
			}
			objects = append(objects, value)
		case "field":
			var value definitionmodel.FieldSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode field definition %s: %w", definition.Key, err)
			}
			fields = append(fields, value)
		case "validation":
			var value definitionmodel.ValidationSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode validation definition %s: %w", definition.Key, err)
			}
			validations = append(validations, value)
		case "action":
			var value definitionmodel.ActionSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode action definition %s: %w", definition.Key, err)
			}
			actions = append(actions, value)
		}
	}
	return objects, fields, validations, actions, nil
}

func (r MetadataStore) loadCatalog(ctx context.Context) (map[string]string, error) {
	statement, arguments, err := ormbuilder.NewSelectBuilder(r.store.SQLRenderer, "_identity_manifest_catalog").Columns("key", "value").Build()
	if err != nil {
		return nil, fmt.Errorf("build metadata catalog query: %w", err)
	}
	rows, err := r.database().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("load metadata catalog: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("scan metadata catalog: %w", err)
		}
		out[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read metadata catalog: %w", err)
	}
	if strings.TrimSpace(out["template_id"]) == "" || strings.TrimSpace(out["template_version"]) == "" {
		return nil, fmt.Errorf("metadata catalog is missing template identity")
	}
	return out, nil
}

func loadMetadataSliceContext[T any](ctx context.Context, db *sql.DB, store *database.IdentityStore, table string) ([]T, error) {
	statement, arguments, err := ormbuilder.NewSelectBuilder(store.SQLRenderer, table).Columns("payload_json").Where(ormbuilder.IsNull("disabled_at")).OrderBy(ormbuilder.Ascending("resource_key")).Build()
	if err != nil {
		return nil, fmt.Errorf("build %s query: %w", table, err)
	}
	rows, err := db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", table, err)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan %s: %w", table, err)
		}
		var value T
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, fmt.Errorf("decode %s payload: %w", table, err)
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", table, err)
	}
	return out, nil
}

func (r MetadataStore) ListDefinitions(ctx context.Context, scope identitymodel.SystemScope, resourceType string) ([]metadatamodel.MetadataDefinition, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	if metadataModuleOwnsDefinition(resourceType) {
		return r.ListMetadataDefinitions(ctx, resourceType, "")
	}
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := metadataDefinitionSelect(r, table).Where(ormbuilder.IsNull("disabled_at")).OrderBy(ormbuilder.Ascending("resource_key")).Build()
	if err != nil {
		return nil, fmt.Errorf("build %s definitions query: %w", resourceType, err)
	}
	rows, err := r.database().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list %s definitions: %w", resourceType, err)
	}
	defer rows.Close()
	out := []metadatamodel.MetadataDefinition{}
	for rows.Next() {
		definition, err := scanMetadataDefinition(rows, resourceType)
		if err != nil {
			return nil, err
		}
		out = append(out, definition)
	}
	return out, rows.Err()
}

func (r MetadataStore) GetDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string) (metadatamodel.MetadataDefinition, bool, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	if metadataModuleOwnsDefinition(resourceType) {
		return r.GetMetadataDefinition(ctx, resourceType, resourceKey)
	}
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	statement, arguments, err := metadataDefinitionSelect(r, table).Where(ormbuilder.Equal("resource_key", resourceKey)).Build()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, fmt.Errorf("build %s definition query: %w", resourceType, err)
	}
	definition, err := scanMetadataDefinition(r.database().QueryRowContext(ctx, statement, arguments...), resourceType)
	if err == sql.ErrNoRows {
		return metadatamodel.MetadataDefinition{}, false, nil
	}
	return definition, err == nil, err
}

func metadataDefinitionSelect(r MetadataStore, table string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewSelectBuilder(r.store.SQLRenderer, table).Columns(
		"resource_key", "object_key", "name", "payload_json", "schema_version", "schema_hash", "source_kind", "source_id", "disabled_at", "created_at", "updated_at",
	)
}

type metadataDefinitionScanner interface{ Scan(...any) error }

func scanMetadataDefinition(scanner metadataDefinitionScanner, resourceType string) (metadatamodel.MetadataDefinition, error) {
	var definition metadatamodel.MetadataDefinition
	var payload string
	var disabled sql.NullString
	if err := scanner.Scan(&definition.ResourceKey, &definition.ObjectKey, &definition.Name, &payload, &definition.SchemaVersion, &definition.SchemaHash, &definition.SourceKind, &definition.SourceID, &disabled, &definition.CreatedAt, &definition.UpdatedAt); err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	definition.ResourceType = resourceType
	definition.Payload = json.RawMessage(payload)
	if disabled.Valid {
		definition.DisabledAt = disabled.String
	}
	return definition, nil
}

func (r MetadataStore) ListDefinitionVersions(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	return r.ListMetadataDefinitionVersions(ctx, resourceType, resourceKey)
}

func (r MetadataStore) metadataDefinitionReplay(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey, targetHash string, expectedHash *string) (metadatamodel.MetadataDefinition, bool, error) {
	current, found, err := r.GetDefinition(ctx, scope, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	if !found {
		if expectedHash != nil && strings.TrimSpace(*expectedHash) != "" {
			return metadatamodel.MetadataDefinition{}, false, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: strings.TrimSpace(*expectedHash)}
		}
		return metadatamodel.MetadataDefinition{}, false, nil
	}
	expected := ""
	if expectedHash != nil {
		expected = strings.TrimSpace(*expectedHash)
	}
	if current.SchemaHash != targetHash {
		if expectedHash != nil && current.SchemaHash != expected {
			return metadatamodel.MetadataDefinition{}, false, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected, CurrentHash: current.SchemaHash}
		}
		return metadatamodel.MetadataDefinition{}, false, nil
	}
	if expectedHash == nil || expected == current.SchemaHash {
		return current, true, nil
	}
	if expected == "" && strings.TrimSpace(current.SchemaVersion) == "1" {
		return current, true, nil
	}
	versions, err := r.ListDefinitionVersions(ctx, scope, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	for index, version := range versions {
		if version.SchemaVersion == current.SchemaVersion && version.SchemaHash == current.SchemaHash && index+1 < len(versions) && versions[index+1].SchemaHash == expected {
			return current, true, nil
		}
	}
	return metadatamodel.MetadataDefinition{}, false, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected, CurrentHash: current.SchemaHash}
}
