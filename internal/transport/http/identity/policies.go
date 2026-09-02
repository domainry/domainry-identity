package identity

import (
	"net/http"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *IdentityHandler) listIdentityRolePermissions(w http.ResponseWriter, r *http.Request) {
	if h.roleDefinitions != nil {
		configuration, err := h.roleDefinitions.PermissionConfiguration(r.Context(), strings.TrimSpace(r.PathValue("roleID")), h.principal(r))
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		w.Header().Set(identityResourceHashHeader, configuration.SchemaHash)
		w.Header().Set("X-Schema-Version", configuration.SchemaVersion)
		h.writeJSON(w, http.StatusOK, configuration.Permissions)
		return
	}
	assignments, err := h.policies.ListRolePermissionAssignments(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, assignments)
}

func (h *IdentityHandler) publishIdentityRolePermissions(w http.ResponseWriter, r *http.Request) {
	if h.roleDefinitions == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.role_definition_publication_unavailable")
		return
	}
	var request identitymodel.IdentityRolePermissionPublicationRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	request.ExpectedSchemaHash = strings.TrimSpace(r.Header.Get("Expected-Schema-Hash"))
	request.OperationID = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	configuration, err := h.roleDefinitions.PublishPermissions(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	w.Header().Set(identityResourceHashHeader, configuration.SchemaHash)
	w.Header().Set("X-Schema-Version", configuration.SchemaVersion)
	w.Header().Set("Operation-ID", request.OperationID)
	h.writeJSON(w, http.StatusOK, configuration.Permissions)
}

func (h *IdentityHandler) listIdentityRoleDataScopes(w http.ResponseWriter, r *http.Request) {
	if h.roleDefinitions != nil {
		configuration, err := h.roleDefinitions.DataScopeConfiguration(r.Context(), strings.TrimSpace(r.PathValue("roleID")), h.principal(r))
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		w.Header().Set(identityResourceHashHeader, configuration.SchemaHash)
		w.Header().Set("X-Schema-Version", configuration.SchemaVersion)
		h.writeJSON(w, http.StatusOK, configuration.DataScopes)
		return
	}
	scopes, err := h.policies.ListRoleDataScopes(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, scopes)
}

func (h *IdentityHandler) publishIdentityRoleDataScopes(w http.ResponseWriter, r *http.Request) {
	if h.roleDefinitions == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.role_definition_publication_unavailable")
		return
	}
	var request identitymodel.IdentityRoleDataScopePublicationRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	request.ExpectedSchemaHash = strings.TrimSpace(r.Header.Get("Expected-Schema-Hash"))
	request.OperationID = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	configuration, err := h.roleDefinitions.PublishDataScopes(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	w.Header().Set(identityResourceHashHeader, configuration.SchemaHash)
	w.Header().Set("X-Schema-Version", configuration.SchemaVersion)
	w.Header().Set("Operation-ID", request.OperationID)
	h.writeJSON(w, http.StatusOK, configuration.DataScopes)
}

func (h *IdentityHandler) listIdentityRoleFieldPermissions(w http.ResponseWriter, r *http.Request) {
	if h.roleDefinitions != nil {
		configuration, err := h.roleDefinitions.FieldPermissionConfiguration(r.Context(), strings.TrimSpace(r.PathValue("roleID")), h.principal(r))
		if err != nil {
			h.writeServiceError(w, r, err)
			return
		}
		w.Header().Set(identityResourceHashHeader, configuration.SchemaHash)
		w.Header().Set("X-Schema-Version", configuration.SchemaVersion)
		h.writeJSON(w, http.StatusOK, configuration.FieldPermissions)
		return
	}
	permissions, err := h.policies.ListRoleFieldPermissions(r.Context(), strings.TrimSpace(r.PathValue("roleID")))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, permissions)
}

func (h *IdentityHandler) publishIdentityRoleFieldPermissions(w http.ResponseWriter, r *http.Request) {
	if h.roleDefinitions == nil {
		h.writeError(w, r, http.StatusServiceUnavailable, "backend.identity.role_definition_publication_unavailable")
		return
	}
	var request identitymodel.IdentityRoleFieldPermissionPublicationRequest
	if !h.decodeJSON(w, r, &request) {
		return
	}
	request.ExpectedSchemaHash = strings.TrimSpace(r.Header.Get("Expected-Schema-Hash"))
	request.OperationID = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	configuration, err := h.roleDefinitions.PublishFieldPermissions(r.Context(), strings.TrimSpace(r.PathValue("roleID")), request, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	w.Header().Set(identityResourceHashHeader, configuration.SchemaHash)
	w.Header().Set("X-Schema-Version", configuration.SchemaVersion)
	w.Header().Set("Operation-ID", request.OperationID)
	h.writeJSON(w, http.StatusOK, configuration.FieldPermissions)
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
