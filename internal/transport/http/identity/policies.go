package identity

import (
	"net/http"
	"strings"
)

func (h *IdentityHandler) listIdentityRolePermissions(w http.ResponseWriter, r *http.Request) {
	assignments, err := h.policies.ListRolePermissionAssignments(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, assignments)
}

func (h *IdentityHandler) listIdentityRoleDataScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := h.policies.ListRoleDataScopes(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, scopes)
}

func (h *IdentityHandler) listIdentityRoleFieldPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.policies.ListRoleFieldPermissions(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, permissions)
}

func (h *IdentityHandler) appendIdentityMutationAudit(r *http.Request, event string, objectKey string, recordID string, summary string, metadata map[string]any) {
	if h.audit == nil {
		return
	}
	metadata = cloneStringAnyMap(metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["path"] = r.URL.Path
	metadata["method"] = r.Method
	h.audit.AppendWithMetadata(r.Context(), event, objectKey, recordID, h.principal(r), summary, nil, nil, metadata)
}

func cloneStringAnyMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	out := map[string]any{}
	for key, item := range value {
		out[key] = item
	}
	return out
}
