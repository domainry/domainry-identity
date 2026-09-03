package identity

import (
	"net/http"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *IdentityHandler) getIdentityOrganizationUnit(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("organizationUnitID"))
	item, found, err := h.users.OrganizationUnitByIDWithinDataScope(r.Context(), id, h.principal(r), "identity.organization_units.get")
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if found {
		h.writeIdentityAuthoringResource(w, r, "identity.organization_unit", id, item)
		return
	}
	h.writeError(w, r, http.StatusNotFound, "backend.identity.organization_unit_not_found", "organization_unit", id)
}

func (h *IdentityHandler) getIdentityRole(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("roleID"))
	items, err := h.roles.ListRoles(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	for _, item := range items {
		if item.ID == id {
			h.writeIdentityAuthoringResource(w, r, "identity.role", id, item)
			return
		}
	}
	h.writeError(w, r, http.StatusNotFound, "backend.identity.role_not_found", "role", id)
}

func (h *IdentityHandler) getIdentityMenu(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("menuID"))
	items, err := h.menus.ListMenus(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	for _, item := range items {
		if item.ID == id {
			h.writeIdentityAuthoringResource(w, r, "identity.menu", id, item)
			return
		}
	}
	h.writeError(w, r, http.StatusNotFound, "backend.identity.menu_not_found", "menu", id)
}

func (h *IdentityHandler) identityAuthoringVersions(capabilityKey, objectKey, pathKey string, allowedEvents ...string) http.HandlerFunc {
	allowed := make(map[string]bool, len(allowedEvents))
	for _, event := range allowedEvents {
		allowed[event] = true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if h.audit == nil {
			h.writeError(w, r, http.StatusFailedDependency, "backend.identity.authoring_history_unavailable")
			return
		}
		resourceID := strings.TrimSpace(r.PathValue(pathKey))
		principal := h.principal(r)
		visible, err := h.identityAuthoringVersionTargetVisible(r, capabilityKey, resourceID, principal)
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		if !visible {
			h.writeError(w, r, http.StatusNotFound, "backend.identity.authoring_resource_not_found", "resource", resourceID)
			return
		}
		events, err := h.audit.Events(r.Context(), auditmodel.AuditEventQuery{ObjectKey: objectKey, RecordID: resourceID, Limit: 1000}, principal)
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		items := make([]auditmodel.AuditEvent, 0, len(events))
		for _, event := range events {
			if allowed[event.Event] {
				items = append(items, event)
			}
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"capability_key": capabilityKey, "resource_id": resourceID, "versioning": "audit_revision", "items": items, "count": len(items)})
	}
}

func (h *IdentityHandler) identityAuthoringVersionTargetVisible(r *http.Request, capabilityKey, resourceID string, principal identitymodel.Principal) (bool, error) {
	switch capabilityKey {
	case "identity.user":
		_, found, err := h.users.UserByIDWithinDataScope(r.Context(), resourceID, principal, identitycontract.IdentityUsersVersionsPermission)
		return found, err
	case "identity.user_role_assignment":
		_, found, err := h.users.UserByIDWithinDataScope(r.Context(), resourceID, principal, identitycontract.IdentityUserRoleAssignmentsVersionsPermission)
		return found, err
	case "identity.organization_unit":
		_, found, err := h.users.OrganizationUnitByIDWithinDataScope(r.Context(), resourceID, principal, identitycontract.IdentityOrganizationUnitsVersionsPermission)
		return found, err
	default:
		// Roles, menus and role-menu bindings are tenant templates/system
		// resources. Their histories are workspace-scoped, not org-scoped.
		return true, nil
	}
}
