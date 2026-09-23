package metadata

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"

	"context"
	"encoding/json"
	"fmt"

	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"

	metadatasdk "github.com/domainry/domainry-metadata-sdk"
	"github.com/domainry/domainry-orm/query"
)

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
	roles, err := loadIdentityDefinitionPayloads[identitymodel.RoleSchema](ctx, r, "role")
	if err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	profileBindings, err := loadIdentityDefinitionPayloads[identitymodel.IdentityProfileExtension](ctx, r, "identity_profile_binding")
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
	binding := r.store.Metadata()
	if binding == nil || binding.Definitions() == nil {
		return nil, nil, nil, nil, fmt.Errorf("Metadata definition repository is unavailable")
	}
	snapshot, err := binding.Definitions().Snapshot(ctx, metadatasdk.DefinitionQuery{Owner: metadatasdk.DefinitionOwnerMetadata})
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
				return nil, nil, nil, nil, fmt.Errorf("decode object definition %s: %w", definition.ResourceKey, err)
			}
			objects = append(objects, value)
		case "field":
			var value definitionmodel.FieldSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode field definition %s: %w", definition.ResourceKey, err)
			}
			fields = append(fields, value)
		case "validation":
			var value definitionmodel.ValidationSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode validation definition %s: %w", definition.ResourceKey, err)
			}
			validations = append(validations, value)
		case "action":
			var value definitionmodel.ActionSchema
			if err := json.Unmarshal(definition.Payload, &value); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("decode action definition %s: %w", definition.ResourceKey, err)
			}
			actions = append(actions, value)
		}
	}
	return objects, fields, validations, actions, nil
}

func (r MetadataStore) loadCatalog(ctx context.Context) (map[string]string, error) {
	statement, arguments, err := query.NewSelectBuilder(r.store.SQLRenderer, "_identity_manifest_catalog").Columns("key", "value").Build()
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

func (r MetadataStore) ListDefinitions(ctx context.Context, scope identitymodel.SystemScope, resourceType string) ([]metadatamodel.MetadataDefinition, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	if metadataModuleOwnsDefinition(resourceType) {
		return r.ListMetadataDefinitions(ctx, resourceType, "")
	}
	return r.listIdentityDefinitions(ctx, resourceType, "")
}

func (r MetadataStore) GetDefinition(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string) (metadatamodel.MetadataDefinition, bool, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return metadatamodel.MetadataDefinition{}, false, err
	}
	if metadataModuleOwnsDefinition(resourceType) {
		return r.GetMetadataDefinition(ctx, resourceType, resourceKey)
	}
	return r.getIdentityDefinition(ctx, resourceType, resourceKey)
}

func (r MetadataStore) ListDefinitionVersions(ctx context.Context, scope identitymodel.SystemScope, resourceType, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	if err := requireMetadataInstallationScope(scope); err != nil {
		return nil, err
	}
	if metadataModuleOwnsDefinition(resourceType) {
		return r.ListMetadataDefinitionVersions(ctx, resourceType, resourceKey)
	}
	return r.listIdentityDefinitionVersions(ctx, resourceType, resourceKey)
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
