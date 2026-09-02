package identity

import (
	"net/http"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
)

func (h *IdentityHandler) getIdentityOrganizationUnit(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("organizationUnitID"))
	items, err := h.users.ListOrganizationUnits(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	for _, item := range items {
		if item.ID == id {
			h.writeIdentityAuthoringResource(w, r, "identity.organization_unit", id, item)
			return
		}
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
		events, err := h.audit.Events(r.Context(), auditmodel.AuditEventQuery{ObjectKey: objectKey, RecordID: resourceID, Limit: 1000}, h.principal(r))
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
