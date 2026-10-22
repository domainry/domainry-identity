package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/entityid"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *AuthHandler) authExternalAccounts(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusForbidden, "auth.token_required")
		return
	}
	accounts, err := h.externalAccounts.ListExternalAccounts(r.Context(), principal.WorkspaceID, principal.UserID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, accounts)
}

func (h *AuthHandler) authStartExternalAccountLink(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusForbidden, "auth.token_required")
		return
	}
	var req struct {
		ApplicationKey string `json:"application_key"`
		ReturnURL      string `json:"return_url"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	flow, ok := h.providerFlows.(authProviderExternalAccountLinkFlow)
	if !ok {
		h.writeError(w, r, http.StatusServiceUnavailable, "auth.external_account_link_unavailable")
		return
	}
	flowContext := requestcontext.WithWorkspaceID(r.Context(), principal.WorkspaceID)
	result, err := flow.StartExternalAccountLinkForApplication(flowContext, principal.WorkspaceID, principal.UserID, r.PathValue("provider"), req.ApplicationKey, req.ReturnURL)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authUnbindExternalAccount(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusForbidden, "auth.token_required")
		return
	}
	if err := h.externalAccounts.UnbindExternalAccount(r.Context(), principal.WorkspaceID, principal.UserID, r.PathValue("provider"), r.PathValue("accountID")); err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *AuthHandler) authMe(w http.ResponseWriter, r *http.Request) {
	result, err := h.externalAccounts.Me(r.Context(), bearerTokenFromRequest(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authRoleOptions(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	roles, err := h.roleRequests.ListRequestableRoles(requestcontext.WithWorkspaceID(r.Context(), principal.WorkspaceID))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, authRoleOptions(roles))
}

func (h *AuthHandler) authRoleRequests(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	requests, err := h.roleRequests.ListRoleRequests(requestcontext.WithWorkspaceID(r.Context(), principal.WorkspaceID), strings.TrimSpace(r.URL.Query().Get("status")), principal.UserID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, requests)
}

func (h *AuthHandler) authCreateRoleRequest(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(r)
	if !principal.Known {
		h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
		return
	}
	var req struct {
		RoleIDs []string `json:"role_ids"`
		Reason  string   `json:"reason"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	provider, providerSubject := h.primaryExternalAccountForUser(r.Context(), principal.WorkspaceID, principal.UserID)
	roleRequestID, err := entityid.New("rolereq")
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	request, err := h.roleRequests.CreateRoleRequest(requestcontext.WithWorkspaceID(r.Context(), principal.WorkspaceID), identitymodel.IdentityRoleRequest{
		RoleRequestID:   roleRequestID,
		UserID:          principal.UserID,
		RequestedBy:     principal.UserID,
		Provider:        provider,
		ProviderSubject: providerSubject,
		RoleIDs:         req.RoleIDs,
		Reason:          req.Reason,
	})
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.securityAuditForPrincipal(r, principal, "auth_role_request_submitted", "Submitted role request", map[string]any{"request_id": request.RoleRequestID, "role_count": len(request.RoleIDs), "provider": request.Provider})
	h.writeJSON(w, http.StatusCreated, request)
}

func (h *AuthHandler) primaryExternalAccountForUser(ctx context.Context, workspaceID, userID string) (string, string) {
	accounts, err := h.externalAccounts.ListExternalAccounts(ctx, workspaceID, userID)
	if err != nil || len(accounts) == 0 {
		return "", ""
	}
	return accounts[0].Provider, accounts[0].ProviderSubject
}

func authRoleOptions(roles []identitymodel.IdentityRole) []map[string]any {
	out := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		out = append(out, map[string]any{
			"role_id":     role.RoleID,
			"key":         role.Key,
			"label":       role.Label,
			"description": role.Description,
			"status":      role.Status,
		})
	}
	return out
}
