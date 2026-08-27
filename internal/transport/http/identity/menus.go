package identity

import (
	"context"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"net/http"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (h *IdentityHandler) listIdentityPermissions(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, h.localizedIdentityPermissions(r, h.menus.ListPermissions(r.Context())))
}

func (h *IdentityHandler) listIdentityMenus(w http.ResponseWriter, r *http.Request) {
	menus, err := h.menus.ListMenus(r.Context())
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	menus = h.LocalizedMenus(r, menus)
	h.writeJSON(w, http.StatusOK, menus)
}

func (h *IdentityHandler) upsertIdentityMenu(w http.ResponseWriter, r *http.Request) {
	var req identitymodel.IdentityMenu
	if !h.decodeJSON(w, r, &req) {
		return
	}
	menuID := strings.TrimSpace(r.PathValue("menuID"))
	if menuID != "" {
		req.ID = menuID
	}
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.menu", req.ID, "identity.menus.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), req, principal,
		func(ctx context.Context) (any, bool, error) {
			items, loadErr := h.menus.ListMenus(ctx)
			if loadErr != nil {
				return nil, false, loadErr
			}
			for _, item := range items {
				if item.ID == req.ID {
					return item, true, nil
				}
			}
			return nil, false, nil
		},
		func(ctx context.Context) (any, error) {
			if validateErr := h.governance.ValidateMenu(ctx, req, principal); validateErr != nil {
				return nil, validateErr
			}
			if executeErr := h.menus.UpsertMenu(ctx, req); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_menu_upserted", "identity_menu", req.ID, "Upserted identity menu", map[string]any{"key": req.Key, "route": req.Route, "status": req.Status})
			menus, loadErr := h.menus.ListMenus(ctx)
			if loadErr != nil {
				return nil, loadErr
			}
			return h.LocalizedMenus(r, menus), nil
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusOK, result, err)
}

func (h *IdentityHandler) deleteIdentityMenu(w http.ResponseWriter, r *http.Request) {
	menuID := strings.TrimSpace(r.PathValue("menuID"))
	deletedIDs, err := h.menus.RemoveMenu(r.Context(), menuID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.appendIdentityMutationAudit(r, "identity_menu_deleted", "identity_menu", menuID, "Deleted identity menu tree", map[string]any{"deleted_menu_ids": deletedIDs, "deleted_count": len(deletedIDs)})
	h.writeJSON(w, http.StatusOK, map[string]any{"deleted_ids": deletedIDs})
}

func (h *IdentityHandler) LocalizedMenus(r *http.Request, menus []identitymodel.IdentityMenu) []identitymodel.IdentityMenu {
	locale := strings.TrimSpace(r.URL.Query().Get("locale"))
	if locale == "" {
		return menus
	}
	values, err := h.localization.LocalizedTextsForLocale(r.Context(), "default", locale)
	if err != nil || len(values) == 0 {
		return menus
	}
	lookup := identityLocalizedTextLookup(values)
	out := append([]identitymodel.IdentityMenu(nil), menus...)
	for index := range out {
		menu := &out[index]
		key := strings.TrimSpace(menu.Key)
		if key == "" {
			key = strings.TrimSpace(menu.ID)
		}
		if label := lookup[identityLocalizedTextLookupKey("menu", key, "label")]; label != "" {
			menu.Label = label
		} else if name := lookup[identityLocalizedTextLookupKey("menu", key, "name")]; name != "" {
			menu.Label = name
		}
		if description := lookup[identityLocalizedTextLookupKey("menu", key, "description")]; description != "" {
			menu.Description = description
		}
	}
	return out
}

func (h *IdentityHandler) localizedIdentityPermissions(r *http.Request, permissions []identitymodel.IdentityPermissionDefinition) []identitymodel.IdentityPermissionDefinition {
	locale := strings.TrimSpace(r.URL.Query().Get("locale"))
	if locale == "" {
		return permissions
	}
	values, err := h.localization.LocalizedTextsForLocale(r.Context(), "default", locale)
	if err != nil || len(values) == 0 {
		return permissions
	}
	lookup := identityLocalizedTextLookup(values)
	out := append([]identitymodel.IdentityPermissionDefinition(nil), permissions...)
	for index := range out {
		permission := &out[index]
		if label := lookup[identityLocalizedTextLookupKey("permission", permission.Key, "label")]; label != "" {
			permission.Label = label
		} else if name := lookup[identityLocalizedTextLookupKey("permission", permission.Key, "name")]; name != "" {
			permission.Label = name
		}
		if description := lookup[identityLocalizedTextLookupKey("permission", permission.Key, "description")]; description != "" {
			permission.Description = description
		}
		if resourceLabel := lookup[identityLocalizedTextLookupKey("permission", permission.Key, "resource_label")]; resourceLabel != "" {
			permission.ResourceLabel = resourceLabel
		}
	}
	return out
}

func identityLocalizedTextLookup(values []metadatamodel.LocalizedText) map[string]string {
	out := map[string]string{}
	for _, value := range values {
		out[identityLocalizedTextLookupKey(value.EntityType, value.EntityKey, value.Property)] = value.Text
	}
	return out
}

func identityLocalizedTextLookupKey(entityType string, entityKey string, property string) string {
	return strings.TrimSpace(entityType) + "\x00" + strings.TrimSpace(entityKey) + "\x00" + strings.TrimSpace(property)
}

func (h *IdentityHandler) listIdentityRoleMenus(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(r.PathValue("roleID"))
	assignments, err := h.menus.ListRoleMenuAssignments(r.Context(), roleID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	// IdentityRoleMenuAssignment contains only JSON-safe scalar fields.
	resourceHash, _ := identityAuthoringResourceHash("identity.role_menu_assignment", roleID, assignments, len(assignments) > 0)
	w.Header().Set(identityResourceHashHeader, resourceHash)
	h.writeJSON(w, http.StatusOK, assignments)
}

func (h *IdentityHandler) setIdentityRoleMenus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MenuIDs []string `json:"menu_ids"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	roleID := strings.TrimSpace(r.PathValue("roleID"))
	principal := h.principal(r)
	result, err := h.executeIdentityAuthoringUpsert(r.Context(), "identity.role_menu_assignment", roleID, "identity.menus.write", r.Header.Get("Builder-Task-ID"), r.Header.Get("Idempotency-Key"), r.Header.Get("Expected-Schema-Hash"), req, principal,
		func(ctx context.Context) (any, bool, error) {
			items, loadErr := h.menus.ListRoleMenuAssignments(ctx, roleID)
			return items, len(items) > 0, loadErr
		},
		func(ctx context.Context) (any, error) {
			if validateErr := h.governance.ValidateRoleMenus(ctx, roleID, req.MenuIDs, principal); validateErr != nil {
				return nil, validateErr
			}
			if executeErr := h.menus.SetRoleMenus(ctx, roleID, req.MenuIDs); executeErr != nil {
				return nil, executeErr
			}
			h.appendIdentityMutationAudit(r, "identity_role_menus_updated", "identity_role", roleID, "Updated identity role menus", map[string]any{"menu_count": len(req.MenuIDs)})
			return h.menus.ListRoleMenuAssignments(ctx, roleID)
		})
	h.writeIdentityAuthoringResult(w, r, http.StatusOK, result, err)
}
