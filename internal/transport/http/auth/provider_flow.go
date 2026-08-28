package auth

import (
	"net/http"
	"net/url"
	"strings"

	apperror "github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	authcontract "github.com/domainry/domainry-identity/internal/domain/auth/contract"
	authprojection "github.com/domainry/domainry-identity/internal/domain/auth/projection"
)

func (h *AuthHandler) authProviderStart(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	var req struct {
		WorkspaceID    string `json:"workspace_id"`
		ApplicationKey string `json:"application_key"`
		ReturnURL      string `json:"return_url"`
		Phone          string `json:"phone"`
	}
	if r.Method == http.MethodPost && r.Body != nil && r.ContentLength != 0 && !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID := valueOrDefault(req.WorkspaceID, r.URL.Query().Get("workspace_id"))
	workspaceID, ok := h.requireWorkspace(w, r, workspaceID)
	if !ok {
		return
	}
	flowContext := requestcontext.WithWorkspaceID(r.Context(), workspaceID)
	var result authprojection.AuthProviderStartResponse
	var err error
	if extended, ok := h.providerFlows.(authProviderApplicationFlow); ok && (strings.TrimSpace(req.ApplicationKey) != "" || strings.TrimSpace(req.ReturnURL) != "") {
		result, err = extended.StartForApplication(flowContext, workspaceID, provider, r.Method, req.Phone, req.ApplicationKey, req.ReturnURL)
	} else {
		result, err = h.providerFlows.Start(flowContext, workspaceID, provider, r.Method, req.Phone)
	}
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authProviderVerify(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	var req struct {
		WorkspaceID string `json:"workspace_id"`
		State       string `json:"state"`
		Code        string `json:"code"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID, ok := h.requireWorkspace(w, r, req.WorkspaceID)
	if !ok {
		return
	}
	result, err := h.providerFlows.VerifyOTP(requestcontext.WithWorkspaceID(r.Context(), workspaceID), workspaceID, provider, req.State, req.Code)
	if err != nil && apperror.CodeOf(err) == "auth.provider_state_invalid" {
		h.providerFailureAudit(r, provider, "otp_verify")
		h.writeError(w, r, http.StatusForbidden, "auth.provider_state_invalid")
		return
	}
	if err != nil {
		h.providerFailureAudit(r, provider, "external_login")
		h.writeError(w, r, http.StatusForbidden, "auth.external_account_unlinked")
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authProviderExchange(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	var req struct {
		WorkspaceID    string `json:"workspace_id"`
		ApplicationKey string `json:"application_key"`
		Code           string `json:"code"`
	}
	if !h.decodeJSON(w, r, &req) {
		return
	}
	workspaceID, ok := h.requireWorkspace(w, r, req.WorkspaceID)
	if !ok {
		return
	}
	flow, flowOK := h.providerFlows.(authProviderCodeExchangeFlow)
	adapter, adapterOK := h.providerCallback.(authcontract.AuthProviderCodeExchangeAdapter)
	if !flowOK || !adapterOK {
		h.writeError(w, r, http.StatusServiceUnavailable, "auth.provider_code_exchange_unavailable")
		return
	}
	result, err := flow.ExchangeCode(requestcontext.WithWorkspaceID(r.Context(), workspaceID), workspaceID, provider, req.Code, req.ApplicationKey, adapter)
	if err != nil {
		code := apperror.CodeOf(err)
		if code == "auth.provider_not_configured" || code == "auth.provider_exchange_not_supported" || code == "auth.provider_code_required" {
			h.writeServiceError(w, r, err)
			return
		}
		if code == "auth.provider_code_exchange_failed" {
			h.providerFailureAudit(r, provider, "code_exchange")
			h.writeError(w, r, http.StatusBadGateway, "auth.provider_code_exchange_failed")
			return
		}
		h.providerFailureAudit(r, provider, "external_login")
		h.writeError(w, r, http.StatusForbidden, "auth.external_account_unlinked")
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *AuthHandler) authProviderCallback(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	input := callbackInput(r)
	state := strings.TrimSpace(input.Values["state"])
	if state == "" {
		state = strings.TrimSpace(input.Values["RelayState"])
	}
	if !h.requireMutableFederatedLogin(w, r, provider, state) {
		return
	}
	result, challenge, err := h.providerFlows.ExchangeAndCompleteCallbackWithChallenge(r.Context(), provider, state, input, h.providerCallback)
	code := apperror.CodeOf(err)
	if err != nil && (code == "auth.provider_not_configured" || code == "auth.provider_callback_not_supported") {
		h.writeServiceError(w, r, err)
		return
	}
	if err != nil && code == "auth.provider_state_invalid" {
		h.providerFailureAudit(r, provider, "state")
		h.writeError(w, r, http.StatusForbidden, "auth.provider_state_invalid")
		return
	}
	if err != nil && strings.Contains(err.Error(), "token_exchange") {
		h.providerFailureAudit(r, provider, "token_exchange")
		h.writeError(w, r, http.StatusBadGateway, "auth.provider_token_exchange_not_configured")
		return
	}
	if err != nil {
		h.providerFailureAudit(r, provider, "external_login")
		h.writeError(w, r, http.StatusForbidden, "auth.external_account_unlinked")
		return
	}
	if strings.TrimSpace(challenge.ReturnURL) != "" {
		issuer, ok := h.providerFlows.(authAuthorizationCodeIssuer)
		if !ok {
			h.writeError(w, r, http.StatusServiceUnavailable, "auth.authorization_code_store_unavailable")
			return
		}
		code, issueErr := issuer.IssueAuthorizationCode(r.Context(), challenge.ApplicationKey, challenge.ReturnURL, result)
		if issueErr != nil {
			h.writeServiceError(w, r, issueErr)
			return
		}
		redirect, parseErr := url.Parse(challenge.ReturnURL)
		if parseErr != nil {
			h.writeError(w, r, http.StatusBadRequest, "auth.authorization_code_request_invalid")
			return
		}
		query := redirect.Query()
		query.Set("code", code)
		query.Set("state", challenge.State)
		redirect.RawQuery = query.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
