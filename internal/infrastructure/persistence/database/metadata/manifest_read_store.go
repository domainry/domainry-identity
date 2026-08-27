package metadata

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"sort"
	"strconv"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
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
	objects, err := loadMetadataSliceContext[definitionmodel.ObjectSchema](ctx, r.database(), r.store, "object_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	fields, err := loadMetadataSliceContext[definitionmodel.FieldSchema](ctx, r.database(), r.store, "field_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	validations, err := loadMetadataSliceContext[definitionmodel.ValidationSchema](ctx, r.database(), r.store, "validation_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	views, err := loadMetadataSliceContext[definitionmodel.ViewSchema](ctx, r.database(), r.store, "view_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	actions, err := loadMetadataSliceContext[definitionmodel.ActionSchema](ctx, r.database(), r.store, "action_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	roles, err := loadMetadataSliceContext[identitymodel.RoleSchema](ctx, r.database(), r.store, "role_definitions")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	profileBindings, err := loadMetadataSliceContext[identitymodel.IdentityProfileExtension](ctx, r.database(), r.store, "identity_profile_binding_definitions")
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
		Objects: objects, Views: views, Actions: actions, Roles: roles, IdentityProfileExtensions: profileBindings,
	}, nil
}

func (r MetadataStore) loadCatalog(ctx context.Context) (map[string]string, error) {
	rows, err := r.database().QueryContext(ctx, "SELECT "+r.store.Identifier("key")+", "+r.store.Identifier("value")+" FROM "+r.store.TableIdentifier("metadata_catalog"))
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
	rows, err := db.QueryContext(ctx, "SELECT "+store.Identifier("payload_json")+" FROM "+store.TableIdentifier(table)+" WHERE "+store.Identifier("disabled_at")+" IS NULL ORDER BY "+store.Identifier("resource_key")+" ASC")
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
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + strings.Join(database.QuotedColumns(r.store, []string{"resource_key", "object_key", "name", "payload_json", "schema_version", "schema_hash", "source_kind", "source_id", "disabled_at", "created_at", "updated_at"}), ", ") + " FROM " + r.store.TableIdentifier(table) + " WHERE " + r.store.Identifier("disabled_at") + " IS NULL"
	query += " ORDER BY " + r.store.Identifier("resource_key") + " ASC"
	rows, err := r.database().QueryContext(ctx, query)
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
	table, err := metadataDefinitionTable(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	query := "SELECT " + strings.Join(database.QuotedColumns(r.store, []string{"resource_key", "object_key", "name", "payload_json", "schema_version", "schema_hash", "source_kind", "source_id", "disabled_at", "created_at", "updated_at"}), ", ") + " FROM " + r.store.TableIdentifier(table) + " WHERE " + r.store.Identifier("resource_key") + " = " + r.store.Placeholder(1)
	definition, err := scanMetadataDefinition(r.database().QueryRowContext(ctx, query, resourceKey), resourceType)
	if err == sql.ErrNoRows {
		return metadatamodel.MetadataDefinition{}, false, nil
	}
	return definition, err == nil, err
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
	query := "SELECT " + strings.Join(database.QuotedColumns(r.store, []string{"schema_version", "schema_hash", "payload_json", "created_at"}), ", ") + " FROM " + r.store.TableIdentifier("metadata_definition_versions") + " WHERE " + r.store.Identifier("resource_type") + " = " + r.store.Placeholder(1) + " AND " + r.store.Identifier("resource_key") + " = " + r.store.Placeholder(2) + " ORDER BY " + r.store.Identifier("created_at") + " DESC"
	rows, err := r.database().QueryContext(ctx, query, resourceType, resourceKey)
	if err != nil {
		return nil, fmt.Errorf("list versions %s %s: %w", resourceType, resourceKey, err)
	}
	defer rows.Close()
	out := []metadatamodel.MetadataDefinitionVersion{}
	for rows.Next() {
		var version metadatamodel.MetadataDefinitionVersion
		var payload string
		if err := rows.Scan(&version.SchemaVersion, &version.SchemaHash, &payload, &version.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		version.ResourceType, version.ResourceKey, version.Payload = resourceType, resourceKey, json.RawMessage(payload)
		out = append(out, version)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, leftErr := strconv.Atoi(strings.TrimSpace(out[i].SchemaVersion))
		right, rightErr := strconv.Atoi(strings.TrimSpace(out[j].SchemaVersion))
		if leftErr == nil && rightErr == nil && left != right {
			return left > right
		}
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].SchemaVersion > out[j].SchemaVersion
	})
	return out, nil
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
