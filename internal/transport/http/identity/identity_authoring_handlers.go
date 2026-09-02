package identity

import (
	"net/http"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *IdentityHandler) validateIdentityUserAuthoring(w http.ResponseWriter, r *http.Request) {
	var user identitymodel.IdentityUser
	if !h.decodeJSON(w, r, &user) {
		return
	}
	user.ID = valueOrDefault(strings.TrimSpace(r.PathValue("userID")), user.ID)
	if err := h.governance.ValidateUser(r.Context(), user, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": user})
}

func (h *IdentityHandler) validateIdentityOrganizationUnitAuthoring(w http.ResponseWriter, r *http.Request) {
	var organizationUnit identitymodel.IdentityOrganizationUnit
	if !h.decodeJSON(w, r, &organizationUnit) {
		return
	}
	organizationUnit.ID = valueOrDefault(strings.TrimSpace(r.PathValue("organizationUnitID")), organizationUnit.ID)
	if err := h.governance.ValidateOrganizationUnit(r.Context(), organizationUnit, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": organizationUnit})
}

func (h *IdentityHandler) validateIdentityUserRoleAssignmentAuthoring(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RoleID    string  `json:"role_id"`
		ExpiresAt *string `json:"expires_at,omitempty"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	assignment := identitymodel.IdentityUserRoleAssignment{UserID: strings.TrimSpace(r.PathValue("userID")), RoleID: strings.TrimSpace(request.RoleID), ExpiresAt: request.ExpiresAt}
	if err := h.governance.ValidateUserRoleAssignment(r.Context(), assignment, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": assignment})
}

func (h *IdentityHandler) validateIdentityRoleAuthoring(w http.ResponseWriter, r *http.Request) {
	var role identitymodel.IdentityRole
	if !h.decodeJSON(w, r, &role) {
		return
	}
	role.ID = valueOrDefault(strings.TrimSpace(r.PathValue("roleID")), role.ID)
	if err := h.governance.ValidateRole(r.Context(), role, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": role})
}

func (h *IdentityHandler) validateIdentityRolePermissionAuthoring(w http.ResponseWriter, r *http.Request) {
	var request struct {
		PermissionKeys []string `json:"permission_keys"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if err := h.governance.ValidateRolePermissions(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request.PermissionKeys, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": map[string]any{"permission_keys": request.PermissionKeys}})
}

func (h *IdentityHandler) validateIdentityRoleMenuAssignmentAuthoring(w http.ResponseWriter, r *http.Request) {
	var request struct {
		MenuIDs []string `json:"menu_ids"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if err := h.governance.ValidateRoleMenus(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request.MenuIDs, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if err := h.menus.ValidateRoleMenus(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request.MenuIDs); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": map[string]any{"menu_ids": request.MenuIDs}})
}

func (h *IdentityHandler) validateIdentityRoleDataScopeAuthoring(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DataScopes []identitymodel.IdentityDataScopePolicy `json:"data_scopes"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if err := h.governance.ValidateRoleDataScopes(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request.DataScopes, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": map[string]any{"data_scopes": request.DataScopes}})
}

func (h *IdentityHandler) validateIdentityRoleFieldPermissionAuthoring(w http.ResponseWriter, r *http.Request) {
	var request struct {
		FieldPermissions []identitymodel.IdentityFieldPermission `json:"field_permissions"`
	}
	if !h.decodeJSON(w, r, &request) {
		return
	}
	if err := h.governance.ValidateRoleFieldPermissions(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request.FieldPermissions, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": map[string]any{"field_permissions": request.FieldPermissions}})
}

func (h *IdentityHandler) validateIdentityMenuAuthoring(w http.ResponseWriter, r *http.Request) {
	var menu identitymodel.IdentityMenu
	if !h.decodeJSON(w, r, &menu) {
		return
	}
	menu.ID = valueOrDefault(strings.TrimSpace(r.PathValue("menuID")), menu.ID)
	if err := h.governance.ValidateMenu(r.Context(), menu, h.principal(r)); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"valid": true, "normalized": menu})
}
