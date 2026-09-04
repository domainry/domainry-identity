package identity

import (
	"fmt"
	"sort"
	"strings"

	actioncontract "github.com/domainry/domainry-foundation/action"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

// IdentityActionRegistry is an Identity projection over Foundation's shared,
// frozen Action registry. Domain-specific Permission records and usage DTOs
// are derived from that one immutable snapshot and are never registered as a
// second Action authority.
type IdentityActionRegistry struct {
	shared                *actioncontract.Registry
	permissionOwnerByKey  map[string]string
	permissionOwners      map[string]struct{}
	permissionRecordByKey map[string]identitymodel.IdentityPermissionDefinitionRecord
	permissionUsagesByKey map[string][]identitymodel.IdentityActionPermissionUsage
	pagePermissionByRoute map[string]string
}

func NewIdentityActionRegistry(definitions []identitymodel.IdentityActionDefinition) (*IdentityActionRegistry, error) {
	shared := actioncontract.NewRegistry()
	if err := shared.Register(definitions...); err != nil {
		return nil, err
	}
	if err := shared.Freeze(); err != nil {
		return nil, err
	}
	registry := &IdentityActionRegistry{
		shared:                shared,
		permissionOwnerByKey:  map[string]string{},
		permissionOwners:      map[string]struct{}{},
		permissionRecordByKey: map[string]identitymodel.IdentityPermissionDefinitionRecord{},
		permissionUsagesByKey: map[string][]identitymodel.IdentityActionPermissionUsage{},
		pagePermissionByRoute: map[string]string{},
	}
	for _, definition := range shared.Definitions() {
		for _, page := range definition.Pages {
			if definition.Permission == nil || definition.Permission.Key != definition.Key {
				return nil, fmt.Errorf("page %q action %q has no same-key permission", page.Route, definition.Key)
			}
			if existing := registry.pagePermissionByRoute[page.Route]; existing != "" && existing != definition.Key {
				return nil, fmt.Errorf("page %q is owned by both actions %q and %q", page.Route, existing, definition.Key)
			}
			registry.pagePermissionByRoute[page.Route] = definition.Key
		}
		if definition.Permission == nil {
			continue
		}
		permission := *definition.Permission
		registry.permissionOwnerByKey[permission.Key] = permission.Owner
		registry.permissionOwners[permission.Owner] = struct{}{}
		registry.permissionRecordByKey[permission.Key] = identitymodel.IdentityPermissionDefinitionRecord{
			PermissionKey: permission.Key, ResourceKey: permission.ResourceKey, OperationKey: permission.OperationKey,
			Label: permission.Label, Description: permission.Description, Category: permission.Category,
			SourceKind: definition.SourceKind, SourceOwner: permission.Owner,
			DefinitionStatus: identityPermissionLifecycle(permission.LifecycleStatus), Enabled: true,
		}
	}
	for permissionKey, owner := range registry.permissionOwnerByKey {
		for _, usage := range shared.PermissionUsages(owner, permissionKey) {
			registry.permissionUsagesByKey[permissionKey] = append(registry.permissionUsagesByKey[permissionKey], projectIdentityActionPermissionUsage(usage))
		}
	}
	return registry, nil
}

func projectIdentityActionPermissionUsage(usage actioncontract.PermissionUsage) identitymodel.IdentityActionPermissionUsage {
	definition := usage.Action
	projected := identitymodel.IdentityActionPermissionUsage{
		ActionKey: definition.Key, CapabilityKey: definition.CapabilityKey, CapabilityLabel: definition.CapabilityLabel,
		OperationKey: definition.OperationKey, OperationLabel: definition.OperationLabel,
		ActionLabel: definition.Label,
		RiskLevel:   string(definition.RiskLevel), ApprovalRequired: len(definition.ApprovalPolicies) != 0,
		AssuranceRequired: append([]string(nil), definition.AssuranceRequired...), LifecycleStatus: string(definition.LifecycleStatus),
	}
	if definition.HTTP != nil {
		projected.HTTPMethod = definition.HTTP.Method
		projected.RouteTemplate = definition.HTTP.RouteTemplate
		projected.DisplayRouteTemplate = definition.HTTP.DisplayRouteTemplate
	}
	if len(definition.Pages) != 0 {
		projected.PageRoute, projected.PageLabel = definition.Pages[0].Route, definition.Pages[0].Label
	}
	return projected
}

// RequiredPermissionsForPage returns the exact entry Action permission for an
// Admin page. Page bindings are validated as one-to-one during registry
// construction, so menu validation cannot accidentally require every Action
// used inside a page.
func (registry *IdentityActionRegistry) RequiredPermissionsForPage(route string) ([]string, bool) {
	if registry == nil {
		return nil, false
	}
	route = strings.TrimSpace(route)
	if permissions, ok := platformAdminPagePermissions(route); ok {
		return permissions, true
	}
	permission := registry.pagePermissionByRoute[route]
	if permission == "" {
		return nil, false
	}
	return []string{permission}, true
}

func identityPermissionLifecycle(status actioncontract.LifecycleStatus) string {
	if status == actioncontract.LifecycleRetired {
		return identitymodel.IdentityPermissionDefinitionRetired
	}
	return identitymodel.IdentityPermissionDefinitionActive
}

func (registry *IdentityActionRegistry) Definition(key string) (identitymodel.IdentityActionDefinition, bool) {
	if registry == nil {
		return identitymodel.IdentityActionDefinition{}, false
	}
	return registry.shared.Definition(key)
}

func (registry *IdentityActionRegistry) Definitions() []identitymodel.IdentityActionDefinition {
	if registry == nil {
		return nil
	}
	return registry.shared.Definitions()
}

func (registry *IdentityActionRegistry) ResolveHTTP(method, routeTemplate string) (identitymodel.IdentityActionDefinition, bool) {
	if registry == nil {
		return identitymodel.IdentityActionDefinition{}, false
	}
	return registry.shared.ResolveHTTP(method, routeTemplate)
}

func (registry *IdentityActionRegistry) ResolveNonHTTP(kind, invocationKey string) (identitymodel.IdentityActionDefinition, bool) {
	if registry == nil {
		return identitymodel.IdentityActionDefinition{}, false
	}
	return registry.shared.ResolveNonHTTP(kind, invocationKey)
}

func (registry *IdentityActionRegistry) OwnedPermissionDefinitions(sourceOwner string) []identitymodel.IdentityPermissionDefinitionRecord {
	if registry == nil {
		return nil
	}
	sourceOwner = strings.TrimSpace(sourceOwner)
	result := []identitymodel.IdentityPermissionDefinitionRecord{}
	for _, definition := range registry.permissionRecordByKey {
		if definition.SourceOwner == sourceOwner {
			result = append(result, definition)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PermissionKey < result[j].PermissionKey })
	return result
}

func (registry *IdentityActionRegistry) PermissionOwners() []string {
	if registry == nil {
		return nil
	}
	owners := make([]string, 0, len(registry.permissionOwners))
	for owner := range registry.permissionOwners {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	return owners
}

// PermissionUsageAvailable reports whether this process has the canonical
// owner's frozen Action registry. A missing owner is not treated as an empty
// registry: remote usage must be queried from that owner or shown unavailable.
func (registry *IdentityActionRegistry) PermissionUsageAvailable(sourceOwner string) bool {
	if registry == nil {
		return false
	}
	_, found := registry.permissionOwners[strings.TrimSpace(sourceOwner)]
	return found
}

func (registry *IdentityActionRegistry) PermissionUsages(permissionKey string) []identitymodel.IdentityActionPermissionUsage {
	if registry == nil {
		return nil
	}
	values := registry.permissionUsagesByKey[strings.TrimSpace(permissionKey)]
	result := make([]identitymodel.IdentityActionPermissionUsage, len(values))
	copy(result, values)
	for index := range result {
		result[index].AssuranceRequired = append([]string(nil), result[index].AssuranceRequired...)
	}
	return result
}

// IdentityActionAuthorizationContext deliberately carries no bypass facts or
// permission-key override. Every Action checks its same-key Permission; target
// data is authorized separately from trusted storage facts.
type IdentityActionAuthorizationContext struct{}

// IdentityActionAuthorizationService is the shared request-path evaluator for
// Identity-owned HTTP adapters. It combines the immutable Action registry with
// the database-backed Permission snapshot; transports only resolve path/body
// facts and never choose a different Permission.
type IdentityActionAuthorizationService struct {
	registry *IdentityActionRegistry
	catalog  *IdentityPermissionCatalogApplicationService
}

func NewIdentityActionAuthorizationService(registry *IdentityActionRegistry, catalog *IdentityPermissionCatalogApplicationService) *IdentityActionAuthorizationService {
	return &IdentityActionAuthorizationService{registry: registry, catalog: catalog}
}

func (service *IdentityActionAuthorizationService) Definition(actionKey string) (identitymodel.IdentityActionDefinition, bool) {
	if service == nil || service.registry == nil {
		return identitymodel.IdentityActionDefinition{}, false
	}
	return service.registry.Definition(actionKey)
}

func (service *IdentityActionAuthorizationService) Allows(action identitymodel.IdentityActionDefinition, principal identitymodel.Principal, _ IdentityActionAuthorizationContext) bool {
	if service == nil {
		return false
	}
	switch action.Authorization.Strategy {
	case actioncontract.AuthorizationAnonymous:
		return true
	case actioncontract.AuthorizationAuthenticated:
		if !principal.Known {
			return false
		}
		if action.Permission == nil {
			return true
		}
		// Source-owned policy keys may add constraints after the exact grant,
		// but they never replace the Permission or its per-Permission data scope.
		// In particular, "self" access is represented by `owner`, not by an
		// authenticated-route bypass.
		return service.allowsExactPermission(action, principal)
	default:
		// Signed Actions are executed by their own credential middleware, never
		// by a human RoleSchema evaluator.
		return false
	}
}

func (service *IdentityActionAuthorizationService) allowsExactPermission(action identitymodel.IdentityActionDefinition, principal identitymodel.Principal) bool {
	return principal.Known && action.Permission != nil && action.Permission.Key == action.Key &&
		service.catalog != nil && service.catalog.PermissionIsExecutable(action.Key) &&
		identitycontract.IdentityRoleHasPermissionKey(principal.Role, action.Key)
}
