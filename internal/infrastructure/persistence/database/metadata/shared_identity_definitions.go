package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	shareddefinition "github.com/domainry/domainry-foundation/definition"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (s MetadataStore) syncIdentityDefinitions(ctx context.Context, tx *sql.Tx, manifest manifestmodel.ManifestSchema) error {
	seeds, err := manifestMetadataSeeds(manifest)
	if err != nil {
		return err
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return err
	}
	values := make([]shareddefinition.Definition, 0, len(seeds))
	for _, seed := range seeds {
		raw, _, err := metadataPayload(seed.Payload)
		if err != nil {
			return fmt.Errorf("encode %s %s: %w", seed.ResourceType, seed.Key, err)
		}
		values = append(values, shareddefinition.Definition{
			Owner: shareddefinition.OwnerIdentity, ResourceType: seed.ResourceType, ResourceKey: seed.Key,
			ObjectKey: seed.ObjectKey, Name: seed.Name, Payload: raw,
		})
	}
	return definitions.ReplaceSourceSnapshot(sharedIdentityDefinitionContext(ctx, tx), shareddefinition.SourceSnapshot{
		Owner: shareddefinition.OwnerIdentity, SchemaVersion: metadataMutationValueOrDefault(manifest.Version, "1"),
		SourceKind: "generated", SourceID: manifestGeneratedSourceID(manifest), Definitions: values,
	})
}

func (s MetadataStore) identityDefinitions() (shareddefinition.StorePort, error) {
	if s.store == nil || s.store.Definitions() == nil {
		return nil, fmt.Errorf("Identity shared Definitions persistence is unavailable")
	}
	return s.store.Definitions(), nil
}

func loadIdentityDefinitionPayloads[T any](ctx context.Context, store MetadataStore, resourceType string) ([]T, error) {
	definitions, err := store.listIdentityDefinitions(ctx, resourceType, "")
	if err != nil {
		return nil, err
	}
	values := make([]T, 0, len(definitions))
	for _, definition := range definitions {
		var value T
		if err := json.Unmarshal(definition.Payload, &value); err != nil {
			return nil, fmt.Errorf("decode %s definition %s: %w", resourceType, definition.ResourceKey, err)
		}
		values = append(values, value)
	}
	return values, nil
}

func identityDefinitionResourceType(resourceType string) (string, error) {
	switch resourceType = strings.TrimSpace(resourceType); resourceType {
	case "role", "identity_profile_binding":
		return resourceType, nil
	default:
		return "", fmt.Errorf("unsupported Identity metadata resource type %q", resourceType)
	}
}

func sharedIdentityDefinitionContext(ctx context.Context, executor *sql.Tx) context.Context {
	if executor == nil {
		return ctx
	}
	return shareddefinition.WithExecutor(ctx, executor)
}

func metadataDefinitionFromShared(value shareddefinition.Definition) metadatamodel.MetadataDefinition {
	return metadatamodel.MetadataDefinition{
		ResourceType: value.ResourceType, ResourceKey: value.ResourceKey, ObjectKey: value.ObjectKey, Name: value.Name,
		Payload: append([]byte(nil), value.Payload...), SchemaVersion: value.SchemaVersion, SchemaHash: value.SchemaHash,
		SourceKind: value.SourceKind, SourceID: value.SourceID, DisabledAt: value.DisabledAt,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func metadataDefinitionVersionFromShared(value shareddefinition.Version) metadatamodel.MetadataDefinitionVersion {
	return metadatamodel.MetadataDefinitionVersion{
		ResourceType: value.ResourceType, ResourceKey: value.ResourceKey, SchemaVersion: value.SchemaVersion,
		SchemaHash: value.SchemaHash, Payload: append([]byte(nil), value.Payload...), CreatedAt: value.CreatedAt,
	}
}

func (s MetadataStore) listIdentityDefinitions(ctx context.Context, resourceType, sourceID string) ([]metadatamodel.MetadataDefinition, error) {
	resourceType, err := identityDefinitionResourceType(resourceType)
	if err != nil {
		return nil, err
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return nil, err
	}
	values, err := definitions.List(ctx, shareddefinition.Query{Owner: shareddefinition.OwnerIdentity, ResourceType: resourceType, SourceID: strings.TrimSpace(sourceID)})
	if err != nil {
		return nil, err
	}
	result := make([]metadatamodel.MetadataDefinition, len(values))
	for index, value := range values {
		result[index] = metadataDefinitionFromShared(value)
	}
	return result, nil
}

func (s MetadataStore) getIdentityDefinition(ctx context.Context, resourceType, resourceKey string) (metadatamodel.MetadataDefinition, bool, error) {
	value, found, err := s.getSharedIdentityDefinition(ctx, resourceType, resourceKey)
	if err != nil || !found {
		return metadatamodel.MetadataDefinition{}, found, err
	}
	return metadataDefinitionFromShared(value), true, nil
}

func (s MetadataStore) getSharedIdentityDefinition(ctx context.Context, resourceType, resourceKey string) (shareddefinition.Definition, bool, error) {
	resourceType, err := identityDefinitionResourceType(resourceType)
	if err != nil {
		return shareddefinition.Definition{}, false, err
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return shareddefinition.Definition{}, false, err
	}
	value, found, err := definitions.Get(ctx, shareddefinition.OwnerIdentity, resourceType, strings.TrimSpace(resourceKey))
	return value, found, err
}

func (s MetadataStore) listIdentityDefinitionVersions(ctx context.Context, resourceType, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	resourceType, err := identityDefinitionResourceType(resourceType)
	if err != nil {
		return nil, err
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return nil, err
	}
	values, err := definitions.ListVersions(ctx, shareddefinition.VersionListQuery{Owner: shareddefinition.OwnerIdentity, ResourceType: resourceType, ResourceKey: strings.TrimSpace(resourceKey)})
	if err != nil {
		return nil, err
	}
	result := make([]metadatamodel.MetadataDefinitionVersion, len(values))
	for index, value := range values {
		result[index] = metadataDefinitionVersionFromShared(value)
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, leftErr := strconv.Atoi(strings.TrimSpace(result[i].SchemaVersion))
		right, rightErr := strconv.Atoi(strings.TrimSpace(result[j].SchemaVersion))
		if leftErr == nil && rightErr == nil && left != right {
			return left > right
		}
		if result[i].CreatedAt != result[j].CreatedAt {
			return result[i].CreatedAt > result[j].CreatedAt
		}
		return result[i].SchemaVersion > result[j].SchemaVersion
	})
	return result, nil
}

func nextIdentityDefinitionVersion(current shareddefinition.Definition, found bool) string {
	if found {
		if value, err := strconv.Atoi(strings.TrimSpace(current.SchemaVersion)); err == nil && value >= 0 {
			return strconv.Itoa(value + 1)
		}
	}
	return "1"
}

func expectedIdentityDefinitionVersion(resourceType, resourceKey string, current shareddefinition.Definition, found bool, expectedHash *string) (string, error) {
	if expectedHash == nil {
		if found {
			return current.CurrentVersionID, nil
		}
		return shareddefinition.NoCurrentVersion, nil
	}
	expected := strings.TrimSpace(*expectedHash)
	if !found {
		if expected == "" {
			return shareddefinition.NoCurrentVersion, nil
		}
		return "", &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected}
	}
	if expected == "" || current.SchemaHash != expected {
		return "", &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected, CurrentHash: current.SchemaHash}
	}
	return current.CurrentVersionID, nil
}

func (s MetadataStore) publishIdentityDefinition(ctx context.Context, tx *sql.Tx, resourceType, resourceKey string, shape metadataDefinitionPayloadShape, raw []byte, hash string, request metadatamodel.MetadataDefinitionUpsertRequest, defaultSourceKind, defaultSourceID string) (metadatamodel.MetadataDefinition, error) {
	resourceType, err := identityDefinitionResourceType(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	definitionContext := sharedIdentityDefinitionContext(ctx, tx)
	current, found, err := definitions.Get(definitionContext, shareddefinition.OwnerIdentity, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	expectedVersion, err := expectedIdentityDefinitionVersion(resourceType, resourceKey, current, found, request.ExpectedSchemaHash)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	sourceKind := metadataMutationValueOrDefault(request.SourceKind, defaultSourceKind)
	sourceID := metadataMutationValueOrDefault(request.SourceID, defaultSourceID)
	result, err := definitions.Publish(definitionContext, shareddefinition.PublishCommand{
		Owner: shareddefinition.OwnerIdentity, ResourceType: resourceType, ResourceKey: resourceKey,
		ExpectedCurrentVersionID: expectedVersion, SchemaVersion: nextIdentityDefinitionVersion(current, found), SchemaHash: hash,
		ObjectKey: shape.ObjectKey, Name: shape.Name, Payload: append([]byte(nil), raw...),
		SourceKind: sourceKind, SourceID: sourceID, PublishedBy: sourceKind + ":" + sourceID,
	})
	if err != nil {
		var sharedError *shareddefinition.Error
		if errors.As(err, &sharedError) && sharedError.Code == "metadata.definition_revision_conflict" {
			expected := ""
			if request.ExpectedSchemaHash != nil {
				expected = strings.TrimSpace(*request.ExpectedSchemaHash)
			}
			return metadatamodel.MetadataDefinition{}, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expected, CurrentHash: current.SchemaHash}
		}
		return metadatamodel.MetadataDefinition{}, err
	}
	return metadataDefinitionFromShared(result.Definition), nil
}

func (s MetadataStore) disableIdentityDefinition(ctx context.Context, tx *sql.Tx, resourceType, resourceKey, expectedHash, disabledBy string) (metadatamodel.MetadataDefinition, error) {
	resourceType, err := identityDefinitionResourceType(resourceType)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	definitions, err := s.identityDefinitions()
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	definitionContext := sharedIdentityDefinitionContext(ctx, tx)
	current, found, err := definitions.Get(definitionContext, shareddefinition.OwnerIdentity, resourceType, resourceKey)
	if err != nil {
		return metadatamodel.MetadataDefinition{}, err
	}
	expectedHash = strings.TrimSpace(expectedHash)
	if !found || expectedHash == "" || current.SchemaHash != expectedHash {
		currentHash := ""
		if found {
			currentHash = current.SchemaHash
		}
		return metadatamodel.MetadataDefinition{}, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expectedHash, CurrentHash: currentHash}
	}
	if err := definitions.Disable(definitionContext, shareddefinition.DisableCommand{
		Owner: shareddefinition.OwnerIdentity, ResourceType: resourceType, ResourceKey: resourceKey,
		ExpectedCurrentVersionID: current.CurrentVersionID, DisabledBy: metadataMutationValueOrDefault(disabledBy, "identity:metadata"),
	}); err != nil {
		var sharedError *shareddefinition.Error
		if errors.As(err, &sharedError) && sharedError.Code == "metadata.definition_revision_conflict" {
			return metadatamodel.MetadataDefinition{}, &metadatamodel.MetadataDefinitionConflictError{ResourceType: resourceType, ResourceKey: resourceKey, ExpectedHash: expectedHash, CurrentHash: current.SchemaHash}
		}
		return metadatamodel.MetadataDefinition{}, err
	}
	current.Status = "disabled"
	current.DisabledAt = time.Now().UTC().Format(time.RFC3339Nano)
	current.UpdatedAt = current.DisabledAt
	return metadataDefinitionFromShared(current), nil
}
