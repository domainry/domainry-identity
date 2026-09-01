package identity

import (
	"fmt"
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityActionRegistry is immutable after construction. S0 resolves route
// registration and permission usage projections from this same snapshot.
type IdentityActionRegistry struct {
	definitions []identitymodel.IdentityActionDefinition
	byKey       map[string]identitymodel.IdentityActionDefinition
	byHTTP      map[string]string
	ownedByKey  map[string]identitymodel.IdentityPermissionDefinitionRecord
	usageByKey  map[string][]identitymodel.IdentityActionPermissionUsage
}

func NewIdentityActionRegistry(definitions []identitymodel.IdentityActionDefinition) (*IdentityActionRegistry, error) {
	registry := &IdentityActionRegistry{
		byKey:      make(map[string]identitymodel.IdentityActionDefinition, len(definitions)),
		byHTTP:     make(map[string]string, len(definitions)),
		ownedByKey: map[string]identitymodel.IdentityPermissionDefinitionRecord{},
		usageByKey: map[string][]identitymodel.IdentityActionPermissionUsage{},
	}
	for index := range definitions {
		definition := cloneIdentityActionDefinition(definitions[index])
		if err := validateIdentityActionDefinition(definition); err != nil {
			return nil, fmt.Errorf("Identity action %d: %w", index, err)
		}
		if _, duplicate := registry.byKey[definition.Key]; duplicate {
			return nil, fmt.Errorf("Identity action key %q is duplicated", definition.Key)
		}
		httpIdentity := definition.HTTP.Method + " " + definition.HTTP.RouteTemplate
		if existing, duplicate := registry.byHTTP[httpIdentity]; duplicate {
			return nil, fmt.Errorf("Identity HTTP action %q is owned by both %q and %q", httpIdentity, existing, definition.Key)
		}
		registry.byKey[definition.Key] = definition
		registry.byHTTP[httpIdentity] = definition.Key
		registry.definitions = append(registry.definitions, definition)
		for _, owned := range definition.OwnedPermissions {
			if current, duplicate := registry.ownedByKey[owned.Key]; duplicate {
				return nil, fmt.Errorf("Identity permission %q has duplicate owners %q and %q", owned.Key, current.SourceOwner, definition.Owner)
			}
			registry.ownedByKey[owned.Key] = identitymodel.IdentityPermissionDefinitionRecord{
				PermissionKey: owned.Key, ResourceKey: owned.ResourceKey, ActionKey: owned.ActionKey,
				Label: owned.Label, Description: owned.Description, Category: owned.Category,
				SourceKind: definition.SourceKind, SourceOwner: definition.Owner,
				DefinitionStatus: identitymodel.IdentityPermissionDefinitionActive, Enabled: true,
			}
		}
	}
	for _, definition := range registry.definitions {
		for _, permission := range definition.RequiredPermissions {
			if _, defined := registry.ownedByKey[permission]; !defined {
				return nil, fmt.Errorf("Identity action %q references permission %q without a canonical owner", definition.Key, permission)
			}
			usage := identitymodel.IdentityActionPermissionUsage{
				ActionKey: definition.Key, CapabilityKey: definition.CapabilityKey, CapabilityLabel: definition.CapabilityLabel,
				OperationKey: definition.OperationKey, OperationLabel: definition.OperationLabel,
				ActionLabel: definition.Label, AuthorizationStrategy: string(definition.AuthorizationStrategy),
				HTTPMethod: definition.HTTP.Method, RouteTemplate: definition.HTTP.RouteTemplate,
				DisplayRouteTemplate: definition.HTTP.DisplayRouteTemplate,
				RiskLevel:            definition.RiskLevel, ApprovalRequired: definition.ApprovalRequired,
				AssuranceRequired: append([]string(nil), definition.AssuranceRequired...), LifecycleStatus: definition.LifecycleStatus,
			}
			if definition.Page != nil {
				usage.PageRoute, usage.PageLabel = definition.Page.Route, definition.Page.Label
			}
			registry.usageByKey[permission] = append(registry.usageByKey[permission], usage)
		}
	}
	sort.Slice(registry.definitions, func(i, j int) bool { return registry.definitions[i].Key < registry.definitions[j].Key })
	for key := range registry.usageByKey {
		sort.Slice(registry.usageByKey[key], func(i, j int) bool {
			left, right := registry.usageByKey[key][i], registry.usageByKey[key][j]
			if left.HTTPMethod != right.HTTPMethod {
				return left.HTTPMethod < right.HTTPMethod
			}
			return left.RouteTemplate < right.RouteTemplate
		})
	}
	return registry, nil
}

func validateIdentityActionDefinition(definition identitymodel.IdentityActionDefinition) error {
	for field, value := range map[string]string{
		"key": definition.Key, "owner": definition.Owner, "source kind": definition.SourceKind,
		"capability key": definition.CapabilityKey, "capability label": definition.CapabilityLabel,
		"operation key": definition.OperationKey, "operation label": definition.OperationLabel,
		"label": definition.Label, "exposure": definition.Exposure, "HTTP method": definition.HTTP.Method,
		"HTTP route template": definition.HTTP.RouteTemplate, "risk level": definition.RiskLevel,
		"audit class": definition.AuditClass, "lifecycle status": definition.LifecycleStatus,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if definition.AuthorizationStrategy != identitymodel.IdentityActionStaticAll {
		return fmt.Errorf("authorization strategy %q is unsupported by the S0 registry", definition.AuthorizationStrategy)
	}
	if len(definition.RequiredPermissions) == 0 {
		return fmt.Errorf("static-all authorization requires a permission")
	}
	seen := map[string]bool{}
	for _, permission := range definition.RequiredPermissions {
		permission = strings.TrimSpace(permission)
		if permission == "" || seen[permission] {
			return fmt.Errorf("required permissions contain an empty or duplicate key")
		}
		seen[permission] = true
	}
	for _, permission := range definition.OwnedPermissions {
		if strings.TrimSpace(permission.Key) == "" || strings.TrimSpace(permission.ResourceKey) == "" ||
			strings.TrimSpace(permission.ActionKey) == "" || strings.TrimSpace(permission.Label) == "" || strings.TrimSpace(permission.Category) == "" {
			return fmt.Errorf("owned permission definition is incomplete")
		}
	}
	return nil
}

func cloneIdentityActionDefinition(definition identitymodel.IdentityActionDefinition) identitymodel.IdentityActionDefinition {
	definition.RequiredPermissions = append([]string(nil), definition.RequiredPermissions...)
	definition.OwnedPermissions = append([]identitymodel.IdentityOwnedPermissionDefinition(nil), definition.OwnedPermissions...)
	definition.AssuranceRequired = append([]string(nil), definition.AssuranceRequired...)
	if definition.Page != nil {
		page := *definition.Page
		definition.Page = &page
	}
	return definition
}

func (registry *IdentityActionRegistry) Definition(key string) (identitymodel.IdentityActionDefinition, bool) {
	if registry == nil {
		return identitymodel.IdentityActionDefinition{}, false
	}
	definition, ok := registry.byKey[strings.TrimSpace(key)]
	return cloneIdentityActionDefinition(definition), ok
}

func (registry *IdentityActionRegistry) Definitions() []identitymodel.IdentityActionDefinition {
	if registry == nil {
		return nil
	}
	out := make([]identitymodel.IdentityActionDefinition, len(registry.definitions))
	for index := range registry.definitions {
		out[index] = cloneIdentityActionDefinition(registry.definitions[index])
	}
	return out
}

func (registry *IdentityActionRegistry) OwnedPermissionDefinitions(sourceOwner string) []identitymodel.IdentityPermissionDefinitionRecord {
	if registry == nil {
		return nil
	}
	out := []identitymodel.IdentityPermissionDefinitionRecord{}
	for _, definition := range registry.ownedByKey {
		if definition.SourceOwner == strings.TrimSpace(sourceOwner) {
			out = append(out, definition)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PermissionKey < out[j].PermissionKey })
	return out
}

func (registry *IdentityActionRegistry) PermissionUsages(permissionKey string) []identitymodel.IdentityActionPermissionUsage {
	if registry == nil {
		return nil
	}
	values := registry.usageByKey[strings.TrimSpace(permissionKey)]
	out := make([]identitymodel.IdentityActionPermissionUsage, len(values))
	copy(out, values)
	for index := range out {
		out[index].AssuranceRequired = append([]string(nil), out[index].AssuranceRequired...)
	}
	return out
}
