package identity

import (
	"context"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identityauthoring "github.com/domainry/domainry-identity/internal/application/authoring"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	metadataapplication "github.com/domainry/domainry-identity/internal/application/metadata"
	authdomain "github.com/domainry/domainry-identity/internal/domain/auth/service"
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
	"net/http"
	"strconv"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type IdentityHandler struct {
	users             *identityapplication.IdentityApplicationService
	roles             *identityapplication.IdentityApplicationService
	policies          *identityapplication.IdentityApplicationService
	menus             *identityapplication.IdentityApplicationService
	authorization     *identityapplication.IdentityApplicationService
	effectiveAccess   IdentityEffectiveAccess
	accessReviews     IdentityAccessReviews
	governance        *identityapplication.IdentityGovernanceApplicationService
	profileBindings   *identityapplication.IdentityProfileBindingApplicationService
	localization      *metadataapplication.MetadataApplicationService
	userSecurity      IdentityUserSecurity
	audit             *auditapplication.AuditApplicationService
	principal         func(*http.Request) identitymodel.Principal
	writeJSON         func(http.ResponseWriter, int, any)
	writeError        func(http.ResponseWriter, *http.Request, int, string, ...string)
	writeServiceError func(http.ResponseWriter, *http.Request, error)
	decodeJSON        func(http.ResponseWriter, *http.Request, any) bool
	securityAudit     func(*http.Request, string, string, map[string]any)
	securityPrincipal func(*http.Request, identitymodel.Principal, string, string, map[string]any)
	authoring         *identityauthoring.Service
	actions           *identityapplication.IdentityActionRegistry
	permissionCatalog *identityapplication.IdentityPermissionCatalogApplicationService
	rolePermissions   *identityapplication.IdentityRolePermissionPublicationService
}

type IdentityUserSecurity interface {
	UserSecurityProfile(context.Context, string, string) (authdomain.UserSecurityProfile, error)
	IssueInitialPassword(context.Context, string, string) (string, error)
	UnlockUser(context.Context, string, string) error
	ForceLogoutUser(context.Context, string, string) (int, error)
	ForceLogoutUserIdempotent(context.Context, identitymodel.Principal, string, string) (authdomain.RevokeOtherSessionsResult, bool, error)
	RevokeMFAFactor(context.Context, string, string, string) error
}

type IdentityUserSecurityBatch interface {
	UserDirectorySecurityProfiles(context.Context, string, []string) (map[string]authdomain.UserSecurityProfile, error)
}

type IdentityDependencies struct {
	Users             *identityapplication.IdentityApplicationService
	Roles             *identityapplication.IdentityApplicationService
	Policies          *identityapplication.IdentityApplicationService
	Menus             *identityapplication.IdentityApplicationService
	Authorization     *identityapplication.IdentityApplicationService
	EffectiveAccess   IdentityEffectiveAccess
	AccessReviews     IdentityAccessReviews
	Governance        *identityapplication.IdentityGovernanceApplicationService
	ProfileBindings   *identityapplication.IdentityProfileBindingApplicationService
	Localization      *metadataapplication.MetadataApplicationService
	UserSecurity      IdentityUserSecurity
	Audit             *auditapplication.AuditApplicationService
	Principal         func(*http.Request) identitymodel.Principal
	WriteJSON         func(http.ResponseWriter, int, any)
	WriteError        func(http.ResponseWriter, *http.Request, int, string, ...string)
	WriteServiceError func(http.ResponseWriter, *http.Request, error)
	DecodeJSON        func(http.ResponseWriter, *http.Request, any) bool
	SecurityAudit     func(*http.Request, string, string, map[string]any)
	SecurityPrincipal func(*http.Request, identitymodel.Principal, string, string, map[string]any)
	Authoring         *identityauthoring.Service
	Actions           *identityapplication.IdentityActionRegistry
	PermissionCatalog *identityapplication.IdentityPermissionCatalogApplicationService
	RolePermissions   *identityapplication.IdentityRolePermissionPublicationService
}

func NewIdentityHandler(deps IdentityDependencies) *IdentityHandler {
	actions := deps.Actions
	if actions == nil {
		actions, _ = identityapplication.NewStandaloneIdentityAuthorizationSliceRegistry()
	}
	return &IdentityHandler{
		users: deps.Users, roles: deps.Roles, policies: deps.Policies, menus: deps.Menus,
		authorization: deps.Authorization, effectiveAccess: deps.EffectiveAccess, accessReviews: deps.AccessReviews, governance: deps.Governance, profileBindings: deps.ProfileBindings, localization: deps.Localization,
		userSecurity: deps.UserSecurity, audit: deps.Audit, principal: deps.Principal,
		writeJSON: deps.WriteJSON, writeError: deps.WriteError, writeServiceError: deps.WriteServiceError,
		decodeJSON: deps.DecodeJSON, securityAudit: deps.SecurityAudit, securityPrincipal: deps.SecurityPrincipal,
		authoring: deps.Authoring,
		actions:   actions, permissionCatalog: deps.PermissionCatalog, rolePermissions: deps.RolePermissions,
	}
}

func intQuery(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

// Admin remains the shared platform-superuser middleware for non-Identity
// control-plane routes. Identity management routes use duty-specific gates.
func (h *IdentityHandler) Admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := h.principal(r)
		if !principal.Known || !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
			h.securityAudit(r, "auth_api_denied", "Platform admin API denied", map[string]any{"path": r.URL.Path, "method": r.Method, "reason": "permission"})
			h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next(w, r)
	}
}

func (h *IdentityHandler) identityPermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := h.principal(r)
		if !principal.Known || !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, permission) {
			h.securityAudit(r, "auth_api_denied", "Identity API permission denied", map[string]any{"path": r.URL.Path, "method": r.Method, "permission": permission})
			h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next(w, r)
	}
}

func (h *IdentityHandler) registerIdentityAction(mux routeRegistrar, actionKey string, next http.HandlerFunc) {
	action, ok := h.actions.Definition(actionKey)
	if !ok {
		panic("Identity route references unregistered action " + actionKey)
	}
	mux.HandleFunc(action.HTTP.Method+" "+action.HTTP.RouteTemplate, h.identityAction(action, next))
}

func (h *IdentityHandler) identityAction(action identitymodel.IdentityActionDefinition, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := h.principal(r)
		if action.AuthorizationStrategy != identitymodel.IdentityActionStaticAll {
			h.securityAudit(r, "auth_api_denied", "Identity API action strategy unsupported", map[string]any{"action_key": action.Key, "path": r.URL.Path, "method": r.Method})
			h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		for _, permission := range action.RequiredPermissions {
			if h.permissionCatalog != nil && !h.permissionCatalog.PermissionIsExecutable(permission) {
				h.securityAudit(r, "auth_api_denied", "Identity API action permission is not executable", map[string]any{"action_key": action.Key, "path": r.URL.Path, "method": r.Method, "permission": permission})
				h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
				return
			}
			if !principal.Known || !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, permission) {
				h.securityAudit(r, "auth_api_denied", "Identity API action permission denied", map[string]any{"action_key": action.Key, "path": r.URL.Path, "method": r.Method, "permission": permission})
				h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
				return
			}
		}
		next(w, r)
	}
}

func (h *IdentityHandler) identityPermissions(permissions []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := h.principal(r)
		for _, permission := range permissions {
			if !principal.Known || !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, permission) {
				h.securityAudit(r, "auth_api_denied", "Identity API permissions denied", map[string]any{"path": r.URL.Path, "method": r.Method, "permission": permission})
				h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
				return
			}
		}
		next(w, r)
	}
}

func (h *IdentityHandler) identityPermissionOrSelf(permission, userPathKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := h.principal(r)
		isSelf := principal.Known && strings.TrimSpace(r.PathValue(userPathKey)) == principal.UserID
		if !isSelf && (!principal.Known || !identitypolicy.IdentityRoleHasPermissionKey(principal.Role, permission)) {
			h.securityAudit(r, "auth_api_denied", "Identity API permission denied", map[string]any{"path": r.URL.Path, "method": r.Method, "permission": permission})
			h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next(w, r)
	}
}

func (h *IdentityHandler) Authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.principal(r).Known {
			h.securityAudit(r, "auth_api_denied", "Authenticated Runtime API denied", map[string]any{"path": r.URL.Path, "method": r.Method, "reason": "identity"})
			h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next(w, r)
	}
}

func (h *IdentityHandler) EffectiveMenus(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
		return
	}
	menus, err := h.authorization.ResolveEffectiveMenus(r.Context(), principal.UserID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, h.LocalizedMenus(r, menus))
}

func (h *IdentityHandler) listIdentityDepartments(w http.ResponseWriter, r *http.Request) {
	departments, err := h.users.ListDepartments(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, departments)
}

func (h *IdentityHandler) createIdentityDepartment(w http.ResponseWriter, r *http.Request) {
	var department identitymodel.IdentityDepartment
	if !h.decodeJSON(w, r, &department) {
		return
	}
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.department", department.ID, "identity.departments.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), department, principal,
		func(ctx context.Context) (any, bool, error) {
			items, loadErr := h.users.ListDepartments(ctx)
			if loadErr != nil {
				return nil, false, loadErr
			}
			for _, item := range items {
				if item.ID == department.ID {
					return item, true, nil
				}
			}
			return nil, false, nil
		},
		func(ctx context.Context) (any, error) {
			if executeErr := h.users.UpsertDepartment(ctx, department); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_department_created", "identity_department", department.ID, "Created identity department", map[string]any{"name": department.Name})
			return department, nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusCreated, result, err)
}

func (h *IdentityHandler) updateIdentityDepartment(w http.ResponseWriter, r *http.Request) {
	var department identitymodel.IdentityDepartment
	if !h.decodeJSON(w, r, &department) {
		return
	}
	department.ID = valueOrDefault(strings.TrimSpace(r.PathValue("departmentID")), department.ID)
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.department", department.ID, "identity.departments.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), department, principal,
		func(ctx context.Context) (any, bool, error) {
			items, loadErr := h.users.ListDepartments(ctx)
			if loadErr != nil {
				return nil, false, loadErr
			}
			for _, item := range items {
				if item.ID == department.ID {
					return item, true, nil
				}
			}
			return nil, false, nil
		},
		func(ctx context.Context) (any, error) {
			if executeErr := h.users.UpsertDepartment(ctx, department); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_department_updated", "identity_department", department.ID, "Updated identity department", map[string]any{"name": department.Name, "status": department.Status})
			return department, nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusOK, result, err)
}
