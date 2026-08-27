package service

import (
	"context"
	"sort"
	"strings"
	"sync"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityrepository "github.com/domainry/domainry-identity/internal/domain/identity/repository"
)

// IdentityDomainService owns identity governance and authorization behavior.
type IdentityDomainService struct {
	repo                identityrepository.IdentityRepository
	permission          map[string]identitymodel.IdentityPermissionDefinition
	permissionMu        *sync.RWMutex
	role                map[string]identitymodel.RoleSchema
	roleMu              *sync.RWMutex
	permissionSets      map[string]identitymodel.IdentityPermissionSet
	permissionSetGroups map[string]identitymodel.IdentityPermissionSetGroup
	guardrails          map[string]identitymodel.IdentityGuardrailPolicy
	authorizationMu     *sync.RWMutex
	validation          *IdentityConfigurationDomainService
	workspace           string
	bindingEligibility  IdentityRoleBindingEligibilityResolver
	organizationScopes  IdentityOrganizationScopeResolver
}

type IdentityRoleBindingEligibilityResolver interface {
	IdentityRoleBindingActive(context.Context, string, string, string, string) (bool, error)
}

type IdentityOrganizationScopeResolver interface {
	ResolveIdentityOrganizationScopes(context.Context, string, []string) (identitymodel.IdentityOrganizationScopeFacts, error)
}

// ForWorkspace returns an immutable workspace-scoped service view. Repository
// calls from an unscoped service are rejected by the repository contract.
func (s *IdentityDomainService) ForWorkspace(workspaceID string) (*IdentityDomainService, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	clone := *s
	clone.workspace = workspace.String()
	clone.validation = s.validation.ForWorkspace(workspace.String())
	return &clone, nil
}

func (s *IdentityDomainService) UseRoleBindingEligibility(resolver IdentityRoleBindingEligibilityResolver) {
	if s != nil {
		s.bindingEligibility = resolver
	}
}

func (s *IdentityDomainService) UseOrganizationScopeResolver(resolver IdentityOrganizationScopeResolver) {
	if s != nil {
		s.organizationScopes = resolver
	}
}

func NewIdentityDomainService(repo identityrepository.IdentityRepository, permissions []identitymodel.IdentityPermissionDefinition) *IdentityDomainService {
	byKey := map[string]identitymodel.IdentityPermissionDefinition{}
	for _, permission := range permissions {
		if permission.Key != "" {
			byKey[permission.Key] = permission
		}
	}
	return &IdentityDomainService{
		repo: repo, permission: byKey, permissionMu: &sync.RWMutex{},
		role: map[string]identitymodel.RoleSchema{}, roleMu: &sync.RWMutex{},
		permissionSets: map[string]identitymodel.IdentityPermissionSet{}, permissionSetGroups: map[string]identitymodel.IdentityPermissionSetGroup{},
		guardrails: map[string]identitymodel.IdentityGuardrailPolicy{}, authorizationMu: &sync.RWMutex{},
		validation: NewIdentityConfigurationDomainService(repo),
	}
}

// ReplaceRoleDefinitions atomically refreshes the published authorization
// policy catalog. IdentityRole remains the directory and assignment identity;
// a matching RoleSchema is the sole source of its runtime permissions and
// row/field policy after publication.
func (s *IdentityDomainService) ReplaceRoleDefinitions(roles []identitymodel.RoleSchema) {
	s.roleMu.Lock()
	defer s.roleMu.Unlock()
	clear(s.role)
	for _, role := range roles {
		if key := strings.TrimSpace(role.Key); key != "" {
			role.Key = key
			s.role[key] = role
		}
	}
}

// ReplaceAuthorizationCatalogs atomically refreshes the reusable authorization
// source catalogs used by Effective Access and impact projections.
func (s *IdentityDomainService) ReplaceAuthorizationCatalogs(sets []identitymodel.IdentityPermissionSet, groups []identitymodel.IdentityPermissionSetGroup, guardrails []identitymodel.IdentityGuardrailPolicy) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	clear(s.permissionSets)
	clear(s.permissionSetGroups)
	clear(s.guardrails)
	for _, set := range sets {
		if key := strings.TrimSpace(set.Key); key != "" {
			set.Key = key
			s.permissionSets[key] = set
		}
	}
	for _, group := range groups {
		if key := strings.TrimSpace(group.Key); key != "" {
			group.Key = key
			s.permissionSetGroups[key] = group
		}
	}
	for _, guardrail := range guardrails {
		if key := strings.TrimSpace(guardrail.Key); key != "" {
			guardrail.Key = key
			s.guardrails[key] = guardrail
		}
	}
}

func (s *IdentityDomainService) PublishedPermissionSets(_ context.Context) []identitymodel.IdentityPermissionSet {
	s.authorizationMu.RLock()
	defer s.authorizationMu.RUnlock()
	out := make([]identitymodel.IdentityPermissionSet, 0, len(s.permissionSets))
	for _, set := range s.permissionSets {
		out = append(out, set)
	}
	sort.Slice(out, func(left, right int) bool { return out[left].Key < out[right].Key })
	return out
}

func (s *IdentityDomainService) PublishedPermissionSetGroups(_ context.Context) []identitymodel.IdentityPermissionSetGroup {
	s.authorizationMu.RLock()
	defer s.authorizationMu.RUnlock()
	out := make([]identitymodel.IdentityPermissionSetGroup, 0, len(s.permissionSetGroups))
	for _, group := range s.permissionSetGroups {
		out = append(out, group)
	}
	sort.Slice(out, func(left, right int) bool { return out[left].Key < out[right].Key })
	return out
}

func (s *IdentityDomainService) PublishedGuardrails(_ context.Context) []identitymodel.IdentityGuardrailPolicy {
	s.authorizationMu.RLock()
	defer s.authorizationMu.RUnlock()
	out := make([]identitymodel.IdentityGuardrailPolicy, 0, len(s.guardrails))
	for _, guardrail := range s.guardrails {
		out = append(out, guardrail)
	}
	sort.Slice(out, func(left, right int) bool { return out[left].Key < out[right].Key })
	return out
}

func (s *IdentityDomainService) publishedRoleDefinition(role identitymodel.IdentityRole) (identitymodel.RoleSchema, bool) {
	s.roleMu.RLock()
	defer s.roleMu.RUnlock()
	for _, key := range []string{strings.TrimSpace(role.Key), strings.TrimSpace(role.ID)} {
		if key == "" {
			continue
		}
		if published, ok := s.role[key]; ok {
			return published, true
		}
	}
	return identitymodel.RoleSchema{}, false
}

func (s *IdentityDomainService) publishedRoleByKey(key string) (identitymodel.RoleSchema, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return identitymodel.RoleSchema{}, false
	}
	s.roleMu.RLock()
	defer s.roleMu.RUnlock()
	role, ok := s.role[key]
	return role, ok
}

// PublishedRoleDefinition returns the immutable authorization definition for a
// directory role key. Directory roles never carry permissions themselves.
func (s *IdentityDomainService) PublishedRoleDefinition(_ context.Context, key string) (identitymodel.RoleSchema, bool) {
	return s.publishedRoleByKey(key)
}

func (s *IdentityDomainService) PublishedRoleDefinitions(_ context.Context) []identitymodel.RoleSchema {
	s.roleMu.RLock()
	defer s.roleMu.RUnlock()
	roles := make([]identitymodel.RoleSchema, 0, len(s.role))
	for _, role := range s.role {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Key < roles[j].Key })
	return roles
}

func (s *IdentityDomainService) Repository() identityrepository.IdentityRepository {
	if s == nil {
		return nil
	}
	return s.repo
}

func (s *IdentityDomainService) WorkspaceID() string {
	if s == nil {
		return ""
	}
	return s.workspace
}

func (s *IdentityDomainService) PermissionDefinitions() map[string]identitymodel.IdentityPermissionDefinition {
	s.permissionMu.RLock()
	defer s.permissionMu.RUnlock()
	out := make(map[string]identitymodel.IdentityPermissionDefinition, len(s.permission))
	for key, permission := range s.permission {
		out[key] = permission
	}
	return out
}

// ReplacePermissionDefinitions refreshes the owner validation catalog in
// place so already-scoped service views observe the same immutable snapshot.
func (s *IdentityDomainService) ReplacePermissionDefinitions(permissions []identitymodel.IdentityPermissionDefinition) {
	s.permissionMu.Lock()
	defer s.permissionMu.Unlock()
	clear(s.permission)
	for _, permission := range permissions {
		if key := strings.TrimSpace(permission.Key); key != "" {
			permission.Key = key
			s.permission[key] = permission
		}
	}
}

func (s *IdentityDomainService) ListPermissions(_ context.Context) []identitymodel.IdentityPermissionDefinition {
	s.permissionMu.RLock()
	defer s.permissionMu.RUnlock()
	values := make([]identitymodel.IdentityPermissionDefinition, 0, len(s.permission))
	for _, permission := range s.permission {
		values = append(values, permission)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	return values
}

func (s *IdentityDomainService) ListMenus(ctx context.Context) ([]identitymodel.IdentityMenu, error) {
	return s.repo.ListIdentityMenus(ctx, s.workspace)
}

func (s *IdentityDomainService) EffectiveMenus(ctx context.Context, userID string) ([]identitymodel.IdentityMenu, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []identitymodel.IdentityMenu{}, nil
	}
	roles, err := s.ActiveRolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	roleIDs := map[string]struct{}{}
	for _, role := range roles {
		roleIDs[role.ID] = struct{}{}
	}
	if len(roleIDs) == 0 {
		return []identitymodel.IdentityMenu{}, nil
	}
	menus, err := s.repo.ListIdentityMenus(ctx, s.workspace)
	if err != nil {
		return nil, err
	}
	menuByID := map[string]identitymodel.IdentityMenu{}
	for _, menu := range menus {
		if menu.Status == "" || menu.Status == identitymodel.IdentityStatusActive {
			menuByID[menu.ID] = menu
			if strings.TrimSpace(menu.Key) != "" {
				menuByID[menu.Key] = menu
			}
		}
	}
	selected := map[string]identitymodel.IdentityMenu{}
	addMenuAndParents := func(menuID string) {
		menu, ok := menuByID[strings.TrimSpace(menuID)]
		if !ok || menu.ID == "" {
			return
		}
		for {
			if _, exists := selected[menu.ID]; exists {
				return
			}
			selected[menu.ID] = menu
			parentID := strings.TrimSpace(menu.ParentID)
			if parentID == "" {
				return
			}
			parent, ok := menuByID[parentID]
			if !ok || parent.ID == menu.ID {
				return
			}
			menu = parent
		}
	}
	for roleID := range roleIDs {
		assignments, err := s.repo.ListIdentityRoleMenuAssignments(ctx, s.workspace, roleID)
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			addMenuAndParents(assignment.MenuID)
		}
	}
	ordered := func(values []identitymodel.IdentityMenu) {
		sort.Slice(values, func(i, j int) bool {
			if values[i].SortOrder == values[j].SortOrder {
				return values[i].Key < values[j].Key
			}
			return values[i].SortOrder < values[j].SortOrder
		})
	}
	children := make(map[string][]identitymodel.IdentityMenu, len(selected))
	roots := make([]identitymodel.IdentityMenu, 0, len(selected))
	for _, menu := range selected {
		parentID := strings.TrimSpace(menu.ParentID)
		if _, parentSelected := selected[parentID]; parentID == "" || !parentSelected || parentID == menu.ID {
			roots = append(roots, menu)
			continue
		}
		children[parentID] = append(children[parentID], menu)
	}
	ordered(roots)
	for parentID := range children {
		ordered(children[parentID])
	}
	out := make([]identitymodel.IdentityMenu, 0, len(selected))
	visited := make(map[string]bool, len(selected))
	var appendTree func(identitymodel.IdentityMenu)
	appendTree = func(menu identitymodel.IdentityMenu) {
		if visited[menu.ID] {
			return
		}
		visited[menu.ID] = true
		out = append(out, menu)
		for _, child := range children[menu.ID] {
			appendTree(child)
		}
	}
	for _, root := range roots {
		appendTree(root)
	}
	leftovers := make([]identitymodel.IdentityMenu, 0)
	for _, menu := range selected {
		if !visited[menu.ID] {
			leftovers = append(leftovers, menu)
		}
	}
	ordered(leftovers)
	for _, menu := range leftovers {
		appendTree(menu)
	}
	return out, nil
}
