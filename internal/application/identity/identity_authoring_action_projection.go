package identity

import (
	"fmt"
	"sort"
	"strings"

	actioncontract "github.com/domainry/domainry-foundation/action"
	authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
)

// IdentityAuthoringActionProjection is the validated authoring view of the
// frozen Identity Action registry. Capability contracts retain their payload
// and lifecycle facts, while operation authorization, effects and permissions
// are resolved from the same Action definitions used by request handling.
type IdentityAuthoringActionProjection struct {
	domain        authoringcontract.CapabilityAuthoringDomain
	actionByRoute map[string]identitymodel.IdentityActionDefinition
}

func (projection *IdentityAuthoringActionProjection) Domain() authoringcontract.CapabilityAuthoringDomain {
	if projection == nil {
		return authoringcontract.CapabilityAuthoringDomain{}
	}
	return cloneIdentityAuthoringDomain(projection.domain)
}

func (projection *IdentityAuthoringActionProjection) ActionForRoute(pattern string) (identitymodel.IdentityActionDefinition, bool) {
	if projection == nil {
		return identitymodel.IdentityActionDefinition{}, false
	}
	action, found := projection.actionByRoute[identityAuthoringRouteIdentity(pattern)]
	if !found {
		return identitymodel.IdentityActionDefinition{}, false
	}
	return actioncontract.CloneDefinition(action), true
}

func (registry *IdentityActionRegistry) ProjectAuthoringDomain(domain authoringcontract.CapabilityAuthoringDomain) (*IdentityAuthoringActionProjection, error) {
	if registry == nil {
		return nil, fmt.Errorf("Identity Action registry is required")
	}
	projected := cloneIdentityAuthoringDomain(domain)
	actionByRoute := map[string]identitymodel.IdentityActionDefinition{}
	for capabilityIndex := range projected.Capabilities {
		capability := &projected.Capabilities[capabilityIndex]
		routes, err := identityAuthoringCapabilityRoutes(*capability)
		if err != nil {
			return nil, err
		}
		permissions := map[string]struct{}{}
		for _, pattern := range routes {
			action, err := registry.resolveAuthoringAction(pattern)
			if err != nil {
				return nil, fmt.Errorf("Identity capability %q route %q: %w", capability.Key, pattern, err)
			}
			identity := identityAuthoringRouteIdentity(pattern)
			if previous, found := actionByRoute[identity]; found && previous.Key != action.Key {
				return nil, fmt.Errorf("Identity authoring route %q resolves to both %q and %q", pattern, previous.Key, action.Key)
			}
			actionByRoute[identity] = action
			if action.Permission != nil {
				if action.Permission.Key != action.Key || action.Permission.Owner != action.Owner {
					return nil, fmt.Errorf("Action %q has no same-key, same-owner Permission", action.Key)
				}
				permissions[action.Key] = struct{}{}
			}
		}
		capability.ConfigurationRoutes = routes
		capability.Permissions = make([]string, 0, len(permissions))
		for permission := range permissions {
			capability.Permissions = append(capability.Permissions, permission)
		}
		sort.Strings(capability.Permissions)
		if capability.Execution == nil {
			return nil, fmt.Errorf("Identity capability %q has no execution contract", capability.Key)
		}
		capability.Execution.PermissionModel = authoringcontract.CapabilityPermissionModelExactAction
	}
	return &IdentityAuthoringActionProjection{domain: projected, actionByRoute: actionByRoute}, nil
}

func (registry *IdentityActionRegistry) resolveAuthoringAction(pattern string) (identitymodel.IdentityActionDefinition, error) {
	method, path, found := strings.Cut(identityAuthoringRouteIdentity(pattern), " ")
	if !found {
		return identitymodel.IdentityActionDefinition{}, fmt.Errorf("invalid method and route template")
	}
	if action, resolved := registry.ResolveHTTP(method, path); resolved {
		return action, nil
	}
	if actionKey, resolved := metadatacontract.VersionedMetadataDefinitionAction(pattern); resolved {
		if action, found := registry.ResolveNonHTTP("application_use_case", actionKey); found {
			return action, nil
		}
		return identitymodel.IdentityActionDefinition{}, fmt.Errorf("metadata Action %q is not registered", actionKey)
	}
	return identitymodel.IdentityActionDefinition{}, fmt.Errorf("route has no canonical Action")
}

func identityAuthoringCapabilityRoutes(capability authoringcontract.CapabilityAuthoringDefinition) ([]string, error) {
	values := append([]string(nil), capability.ConfigurationRoutes...)
	values = append(values, capability.ValidationEndpoint, capability.PreviewEndpoint, capability.SimulationEndpoint)
	if operations := capability.ResourceOperations; operations != nil {
		values = append(values, operations.Validate, operations.Upsert, operations.Get, operations.Versions, operations.Simulate, operations.Rollback, operations.Delete)
	}
	seen := map[string]struct{}{}
	routes := make([]string, 0, len(values))
	for _, value := range values {
		value = identityAuthoringRouteIdentity(value)
		if value == "" {
			continue
		}
		method, path, found := strings.Cut(value, " ")
		if !found || strings.TrimSpace(method) == "" || strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("Identity capability %q has invalid route %q", capability.Key, value)
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		routes = append(routes, value)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("Identity capability %q has no authoring operations", capability.Key)
	}
	sort.Strings(routes)
	return routes, nil
}

func identityAuthoringRouteIdentity(pattern string) string {
	method, path, found := strings.Cut(strings.TrimSpace(pattern), " ")
	if !found {
		return strings.TrimSpace(pattern)
	}
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(path)
}

func cloneIdentityAuthoringDomain(source authoringcontract.CapabilityAuthoringDomain) authoringcontract.CapabilityAuthoringDomain {
	result := source
	result.Capabilities = append([]authoringcontract.CapabilityAuthoringDefinition(nil), source.Capabilities...)
	for index := range result.Capabilities {
		capability := &result.Capabilities[index]
		capability.ConfigurationRoutes = append([]string(nil), capability.ConfigurationRoutes...)
		capability.Permissions = append([]string(nil), capability.Permissions...)
		if capability.Execution != nil {
			execution := *capability.Execution
			capability.Execution = &execution
		}
	}
	return result
}
