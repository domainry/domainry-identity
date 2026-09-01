package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *IdentityDomainService) BuildPrincipal(ctx context.Context, userID string) (identitymodel.Principal, error) {
	if userID == "" {
		userID = "admin"
	}
	user, ok, err := s.userByID(ctx, userID)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive {
		return identitymodel.Principal{UserID: userID, Known: false}, nil
	}
	now := time.Now()
	workforce, activeWorkforceProfileIDs, err := s.resolveWorkforceFacts(ctx, user.ID, now)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	organizationScopes, err := s.resolveOrganizationScopes(ctx, activeWorkforceProfileIDs)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	assignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, user.ID)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	activeRoleIDs := map[string]struct{}{}
	activeAssignments := []identitymodel.IdentityUserRoleAssignment{}
	for _, assignment := range assignments {
		active, activeErr := s.identityRoleAssignmentActive(ctx, assignment, activeWorkforceProfileIDs, now)
		if activeErr != nil {
			return identitymodel.Principal{}, activeErr
		}
		if !active {
			continue
		}
		activeRoleIDs[assignment.RoleID] = struct{}{}
		activeAssignments = append(activeAssignments, assignment)
	}
	role := identitymodel.RoleSchema{
		Key:         "identity_effective",
		Name:        "Identity Effective",
		RecordScope: "all_records",
	}
	permissionSet := map[string]struct{}{}
	activeIdentityRoles := []identitymodel.IdentityRole{}
	activePublishedRoles := []identitymodel.RoleSchema{}
	for _, identityRole := range roles {
		if _, ok := activeRoleIDs[identityRole.ID]; !ok {
			continue
		}
		published, ok := s.publishedRoleDefinition(identityRole)
		if !ok {
			continue
		}
		activeIdentityRoles = append(activeIdentityRoles, identityRole)
		activePublishedRoles = append(activePublishedRoles, published)
		for _, key := range published.Permissions {
			if key = strings.TrimSpace(key); key != "" {
				permissionSet[key] = struct{}{}
			}
		}
		role.DataPermissions = append(role.DataPermissions, published.DataPermissions...)
		role.FieldPermissions = append(role.FieldPermissions, published.FieldPermissions...)
		role.ReferencePermissions = append(role.ReferencePermissions, published.ReferencePermissions...)
		role.ExportRules = append(role.ExportRules, published.ExportRules...)
		role.GrantableRoleKeys = append(role.GrantableRoleKeys, published.GrantableRoleKeys...)
		role.Guardrails = append(role.Guardrails, published.Guardrails...)
	}
	identityCanonicalizeEffectiveRole(&role)
	role.Permissions = make([]string, 0, len(permissionSet))
	for key := range permissionSet {
		role.Permissions = append(role.Permissions, key)
	}
	sort.Strings(role.Permissions)
	role.Permissions = s.identityFilterExecutablePermissions(role.Permissions)
	role.Permissions = identityFilterGuardrailDeniedPermissions(role)
	if len(activeIdentityRoles) == 1 {
		published := activePublishedRoles[0]
		published.Key = valueOrDefault(published.Key, activeIdentityRoles[0].Key)
		published.Name = valueOrDefault(published.Name, activeIdentityRoles[0].Label)
		published.RecordScope = valueOrDefault(published.RecordScope, role.RecordScope)
		identityCanonicalizeEffectiveRole(&published)
		published.Permissions = s.identityFilterExecutablePermissions(published.Permissions)
		published.Permissions = identityFilterGuardrailDeniedPermissions(published)
		role = published
	}
	authorizationRevision := identityAuthorizationRevision(user, workforce, organizationScopes, activeAssignments, activeIdentityRoles, role, identityPermissionStateFingerprint(s.PermissionDefinitions()))
	return identitymodel.Principal{
		UserID:                user.ID,
		WorkspaceID:           s.workspace,
		WorkforceProfileID:    workforce.ProfileID,
		DepartmentID:          workforce.DepartmentID,
		DepartmentPath:        workforce.DepartmentPath,
		ReportingPath:         workforce.ReportingPath,
		ReportingUserIDs:      workforce.ReportingUserIDs,
		TeamIDs:               organizationScopes.TeamIDs,
		StoreIDs:              organizationScopes.StoreIDs,
		TerritoryIDs:          organizationScopes.TerritoryIDs,
		WarehouseIDs:          organizationScopes.WarehouseIDs,
		Role:                  role,
		Known:                 true,
		AuthorizationRevision: authorizationRevision,
	}, nil
}

func (s *IdentityDomainService) BuildPrincipalForRole(ctx context.Context, userID string, roleKey string) (identitymodel.Principal, error) {
	roleKey = strings.TrimSpace(roleKey)
	if userID == "" {
		userID = "admin"
	}
	user, ok, err := s.userByID(ctx, userID)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	if !ok || user.Status != identitymodel.IdentityStatusActive || roleKey == "" {
		return identitymodel.Principal{UserID: userID, Known: false}, nil
	}
	now := time.Now()
	workforce, activeWorkforceProfileIDs, err := s.resolveWorkforceFacts(ctx, user.ID, now)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	organizationScopes, err := s.resolveOrganizationScopes(ctx, activeWorkforceProfileIDs)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	userAssignments, err := s.repo.ListIdentityUserRoleAssignments(ctx, s.workspace, user.ID)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	roles, err := s.repo.ListIdentityRoles(ctx, s.workspace)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	var identityRole identitymodel.IdentityRole
	found := false
	for _, role := range roles {
		if (role.Status == "" || role.Status == identitymodel.IdentityStatusActive) && (role.ID == roleKey || role.Key == roleKey) {
			identityRole = role
			found = true
			break
		}
	}
	if !found {
		return identitymodel.Principal{UserID: user.ID, Known: false}, nil
	}
	assigned := false
	var activeAssignment identitymodel.IdentityUserRoleAssignment
	for _, assignment := range userAssignments {
		active, activeErr := s.identityRoleAssignmentActive(ctx, assignment, activeWorkforceProfileIDs, now)
		if activeErr != nil {
			return identitymodel.Principal{}, activeErr
		}
		if assignment.RoleID == identityRole.ID && active {
			assigned = true
			activeAssignment = assignment
			break
		}
	}
	if !assigned {
		return identitymodel.Principal{UserID: user.ID, Known: false}, nil
	}
	published, ok := s.publishedRoleDefinition(identityRole)
	if !ok {
		return identitymodel.Principal{UserID: user.ID, Known: false}, nil
	}
	published.Key = valueOrDefault(published.Key, identityRole.Key)
	published.Name = valueOrDefault(published.Name, identityRole.Label)
	// BuildPrincipal and BuildPrincipalForRole are two entry points into the
	// same authorization fact. Keep every set-like role collection canonical so
	// a bearer-session request and a durable worker reauthorization produce the
	// same RoleSchema and authorization revision.
	identityCanonicalizeEffectiveRole(&published)
	published.Permissions = s.identityFilterExecutablePermissions(published.Permissions)
	published.Permissions = identityFilterGuardrailDeniedPermissions(published)
	authorizationRevision := identityAuthorizationRevision(user, workforce, organizationScopes, []identitymodel.IdentityUserRoleAssignment{activeAssignment}, []identitymodel.IdentityRole{identityRole}, published, identityPermissionStateFingerprint(s.PermissionDefinitions()))
	return identitymodel.Principal{
		UserID:                user.ID,
		WorkspaceID:           s.workspace,
		WorkforceProfileID:    workforce.ProfileID,
		DepartmentID:          workforce.DepartmentID,
		DepartmentPath:        workforce.DepartmentPath,
		ReportingPath:         workforce.ReportingPath,
		ReportingUserIDs:      workforce.ReportingUserIDs,
		TeamIDs:               organizationScopes.TeamIDs,
		StoreIDs:              organizationScopes.StoreIDs,
		TerritoryIDs:          organizationScopes.TerritoryIDs,
		WarehouseIDs:          organizationScopes.WarehouseIDs,
		Role:                  published,
		Known:                 true,
		AuthorizationRevision: authorizationRevision,
	}, nil
}

// identityFilterExecutablePermissions compiles RoleSchema grants against the
// current database-backed PermissionDefinition snapshot. RoleSchema remains
// the grant authority, while an unknown, retired, or administratively disabled
// Permission can never enter a newly resolved principal.
func (s *IdentityDomainService) identityFilterExecutablePermissions(keys []string) []string {
	definitions := s.PermissionDefinitions()
	filtered := make([]string, 0, len(keys))
	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		definition, found := definitions[key]
		if !found || definition.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive || !definition.Enabled {
			continue
		}
		filtered = append(filtered, key)
	}
	return identityUniqueSortedStrings(filtered)
}

func identityAuthorizationRevision(user identitymodel.IdentityUser, workforce identityWorkforceFacts, organizationScopes identitymodel.IdentityOrganizationScopeFacts, assignments []identitymodel.IdentityUserRoleAssignment, roles []identitymodel.IdentityRole, role identitymodel.RoleSchema, permissionStateFingerprint string) string {
	sort.Slice(assignments, func(left, right int) bool {
		return identityCanonicalJSON(assignments[left]) < identityCanonicalJSON(assignments[right])
	})
	sort.Slice(roles, func(left, right int) bool {
		return identityCanonicalJSON(roles[left]) < identityCanonicalJSON(roles[right])
	})
	encoded, _ := json.Marshal(struct {
		User              identitymodel.IdentityUser                   `json:"user"`
		WorkforceRevision string                                       `json:"workforce_revision"`
		Workforce         identityWorkforceFacts                       `json:"workforce"`
		OrganizationScope identitymodel.IdentityOrganizationScopeFacts `json:"organization_scope"`
		Assignments       []identitymodel.IdentityUserRoleAssignment   `json:"assignments"`
		Roles             []identitymodel.IdentityRole                 `json:"roles"`
		EffectiveRole     identitymodel.RoleSchema                     `json:"effective_role"`
		PermissionState   string                                       `json:"permission_state"`
	}{user, workforce.Revision, workforce, organizationScopes, assignments, roles, role, permissionStateFingerprint})
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

// identityPermissionStateFingerprint captures the authorization-relevant
// current database snapshot without coupling bearer revisions to labels or
// timestamps. Any key becoming unknown, disabled, retired, or active changes
// the fingerprint, including when that key is not granted by the current role.
func identityPermissionStateFingerprint(definitions map[string]identitymodel.IdentityPermissionDefinition) string {
	type state struct {
		Key     string `json:"key"`
		Status  string `json:"status"`
		Enabled bool   `json:"enabled"`
	}
	values := make([]state, 0, len(definitions))
	for key, definition := range definitions {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		values = append(values, state{Key: key, Status: strings.TrimSpace(definition.DefinitionStatus), Enabled: definition.Enabled})
	}
	sort.Slice(values, func(left, right int) bool { return values[left].Key < values[right].Key })
	encoded, _ := json.Marshal(values)
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

func (s *IdentityDomainService) resolveOrganizationScopes(ctx context.Context, activeProfileIDs map[string]bool) (identitymodel.IdentityOrganizationScopeFacts, error) {
	if s.organizationScopes == nil || len(activeProfileIDs) == 0 {
		return identitymodel.IdentityOrganizationScopeFacts{}, nil
	}
	profileIDs := make([]string, 0, len(activeProfileIDs))
	for id := range activeProfileIDs {
		profileIDs = append(profileIDs, id)
	}
	sort.Strings(profileIDs)
	return s.organizationScopes.ResolveIdentityOrganizationScopes(ctx, s.workspace, profileIDs)
}

func (s *IdentityDomainService) EffectivePermissionKeys(ctx context.Context, userID string) ([]string, error) {
	principal, err := s.BuildPrincipal(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !principal.Known {
		return []string{}, nil
	}
	return append([]string(nil), principal.Role.Permissions...), nil
}

func identityCanonicalizeEffectiveRole(role *identitymodel.RoleSchema) {
	role.Permissions = identityUniqueSortedStrings(role.Permissions)
	sort.Slice(role.DataPermissions, func(left, right int) bool {
		return identityCanonicalJSON(role.DataPermissions[left]) < identityCanonicalJSON(role.DataPermissions[right])
	})
	sort.Slice(role.FieldPermissions, func(left, right int) bool {
		return identityCanonicalJSON(role.FieldPermissions[left]) < identityCanonicalJSON(role.FieldPermissions[right])
	})
	sort.Slice(role.ReferencePermissions, func(left, right int) bool {
		return identityCanonicalJSON(role.ReferencePermissions[left]) < identityCanonicalJSON(role.ReferencePermissions[right])
	})
	sort.Slice(role.ExportRules, func(left, right int) bool {
		return identityCanonicalJSON(role.ExportRules[left]) < identityCanonicalJSON(role.ExportRules[right])
	})
	sort.Slice(role.Guardrails, func(left, right int) bool {
		return identityCanonicalJSON(role.Guardrails[left]) < identityCanonicalJSON(role.Guardrails[right])
	})
	role.GrantableRoleKeys = identityUniqueSortedStrings(role.GrantableRoleKeys)
}

func identityFilterGuardrailDeniedPermissions(role identitymodel.RoleSchema) []string {
	out := make([]string, 0, len(role.Permissions))
	for _, permission := range role.Permissions {
		if !identitycontract.IdentityRoleGuardrailDeniesPermission(role, permission) {
			out = append(out, permission)
		}
	}
	return out
}

func (s *IdentityDomainService) identityRoleAssignmentActive(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment, activeWorkforceProfileIDs map[string]bool, now time.Time) (bool, error) {
	if !identityRoleAssignmentActiveForWorkforce(assignment, activeWorkforceProfileIDs, now) {
		return false, nil
	}
	if strings.TrimSpace(assignment.BindingKey) == "" && strings.TrimSpace(assignment.ProfileID) == "" {
		return true, nil
	}
	if strings.TrimSpace(assignment.BindingKey) == "" || strings.TrimSpace(assignment.ProfileID) == "" || s.bindingEligibility == nil {
		return false, nil
	}
	return s.bindingEligibility.IdentityRoleBindingActive(ctx, s.workspace, assignment.BindingKey, assignment.ProfileID, assignment.UserID)
}

func identityUniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func identityCanonicalJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func cloneIdentityPolicyExpression(value *identitymodel.IdentityPolicyExpression) *identitymodel.IdentityPolicyExpression {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Path = append([]identitymodel.IdentityPolicyRelationSegment(nil), value.Path...)
	cloned.Values = append([]string(nil), value.Values...)
	cloned.Children = make([]identitymodel.IdentityPolicyExpression, len(value.Children))
	for index := range value.Children {
		child := cloneIdentityPolicyExpression(&value.Children[index])
		cloned.Children[index] = *child
	}
	return &cloned
}

func cloneContextualFieldPolicies(values []identitymodel.ContextualFieldPolicyRule) []identitymodel.ContextualFieldPolicyRule {
	out := append([]identitymodel.ContextualFieldPolicyRule(nil), values...)
	for index := range out {
		out[index].Actions = append([]string(nil), values[index].Actions...)
		out[index].Predicate = cloneIdentityPolicyExpression(values[index].Predicate)
		if values[index].MaskStrategy != nil {
			mask := *values[index].MaskStrategy
			out[index].MaskStrategy = &mask
		}
	}
	return out
}
