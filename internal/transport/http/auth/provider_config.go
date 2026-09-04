package auth

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
)

var (
	buildAuthProviderProbeRequest = func(method, url string, body io.Reader) (*http.Request, error) {
		return http.NewRequest(method, url, body)
	}
	executeAuthProviderProbeRequest = (&http.Client{Timeout: 5 * time.Second}).Do
)

func (h *AuthHandler) authProviders(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, h.providerConfiguration.ListSafe(r.Context()))
}

func (h *AuthHandler) authProviderSetupCheck(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	config, ok := h.authProviderConfig(r.Context(), provider)
	if !ok {
		h.writeError(w, r, http.StatusNotFound, "auth.provider_unknown")
		return
	}
	h.writeJSON(w, http.StatusOK, h.authProviderSetupResult(config))
}

func (h *AuthHandler) authProviderSetupSave(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	var req authmodel.AuthProviderCredentialUpsertRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}
	nextConfig, err := h.providerConfiguration.SaveSetup(r.Context(), provider, req, h.principal(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"provider":    nextConfig.SafeMap(),
		"setup_check": h.authProviderSetupResult(nextConfig),
		"effective":   true,
	})
}

func (h *AuthHandler) authProviderSetupResult(config authmodel.AuthProviderConfig) map[string]any {
	raw := config.Map()
	providerType, enabled := config.Type, config.Enabled
	result := map[string]any{
		"provider":       config.Key,
		"label":          config.Label,
		"type":           providerType,
		"enabled":        enabled,
		"checks":         authProviderSetupChecks(raw),
		"can_auto_fetch": false,
		"next_steps":     authProviderSetupNextSteps(raw),
	}
	if providerType == "oidc" {
		result["redirect_url"] = config.RedirectURL
		result["scope"] = config.Scope
	}
	if !enabled {
		result["status"] = "blocked_missing_configuration"
		return result
	}
	switch strings.ToLower(config.Key) {
	case "feishu", "lark":
		result["can_auto_fetch"] = true
		result["remote_check"] = h.checkFeishuProviderConfig(raw)
	default:
		result["status"] = "configured_manual_provider_review_required"
		result["remote_check"] = map[string]any{
			"status": "not_implemented_for_provider",
			"reason": "provider_specific_metadata_probe_not_bound_yet",
		}
	}
	return result
}

func (h *AuthHandler) enabledAuthProvider(ctx context.Context, provider string) (authmodel.AuthProviderConfig, bool) {
	return h.providerConfiguration.Enabled(ctx, provider)
}

func (h *AuthHandler) authProviderConfig(ctx context.Context, provider string) (authmodel.AuthProviderConfig, bool) {
	return h.providerConfiguration.Find(ctx, provider)
}

func (h *AuthHandler) externalLoginPolicy(ctx context.Context, config authmodel.AuthProviderConfig) authmodel.AuthExternalLoginPolicy {
	return h.providerConfiguration.AuthExternalLoginPolicy(ctx, config)
}

func authProviderSetupChecks(config map[string]any) []map[string]any {
	providerType := stringFromProviderConfig(config, "type")
	switch providerType {
	case "otp":
		return []map[string]any{
			{"key": "provider", "ok": stringFromProviderConfig(config, "otp_provider") != "", "label": "OTP provider"},
			{"key": "connection_key", "ok": stringFromProviderConfig(config, "connection_key") != "", "label": "Integration connection"},
		}
	case "code_exchange", "wechat_mini_program":
		checks := []map[string]any{
			{"key": "client_id", "ok": stringFromProviderConfig(config, "client_id") != "", "label": "App ID"},
			{"key": "client_secret", "ok": boolFromProviderConfig(config, "client_secret_configured"), "label": "App Secret"},
		}
		if strings.EqualFold(stringFromProviderConfig(config, "adapter"), "line_liff") {
			return checks[:1]
		}
		if strings.EqualFold(stringFromProviderConfig(config, "adapter"), "alipay_mini_program") {
			checks[1]["label"] = "Application private key"
			checks = append(checks, map[string]any{"key": "verification_key", "ok": boolFromProviderConfig(config, "verification_key_configured"), "label": "Alipay public key"})
		}
		return checks
	default:
		return []map[string]any{
			{"key": "client_id", "ok": stringFromProviderConfig(config, "client_id") != "", "label": "Client ID / App ID"},
			{"key": "client_secret", "ok": boolFromProviderConfig(config, "client_secret_configured"), "label": "Client Secret / App Secret"},
			{"key": "redirect_url", "ok": stringFromProviderConfig(config, "redirect_url") != "", "label": "Redirect URL"},
		}
	}
}

func authProviderSetupNextSteps(config map[string]any) []string {
	steps := []string{}
	for _, check := range authProviderSetupChecks(config) {
		ok, _ := check["ok"].(bool)
		if ok {
			continue
		}
		steps = append(steps, "configure_"+stringFromAny(check["key"]))
	}
	if len(steps) == 0 {
		steps = append(steps, "run_provider_remote_check")
	}
	return steps
}

func (h *AuthHandler) checkFeishuProviderConfig(config map[string]any) map[string]any {
	appID := stringFromProviderConfig(config, "client_id")
	appSecret := stringFromProviderConfig(config, "client_secret")
	if strings.HasPrefix(appID, "mock") || strings.HasPrefix(appSecret, "mock") {
		return map[string]any{
			"status":    "ok",
			"mode":      "mock",
			"app_id":    appID,
			"can_login": true,
			"checks": []map[string]any{
				{"key": "app_token", "ok": true, "label": "Feishu app_access_token"},
				{"key": "redirect_url", "ok": stringFromProviderConfig(config, "redirect_url") != "", "label": "Redirect URL configured locally"},
			},
		}
	}
	payload, _ := json.Marshal(map[string]string{"app_id": appID, "app_secret": appSecret})
	probeURL := "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
	if strings.EqualFold(stringFromProviderConfig(config, "key"), "lark") {
		probeURL = "https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal"
	}
	req, err := buildAuthProviderProbeRequest(http.MethodPost, probeURL, bytes.NewReader(payload))
	if err != nil {
		return map[string]any{"status": "failed", "reason": "build_request_failed"}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := executeAuthProviderProbeRequest(req)
	if err != nil {
		return map[string]any{"status": "failed", "reason": "request_failed", "error_code": apperror.CodeOf(err)}
	}
	defer resp.Body.Close()
	var parsed struct {
		Code           int    `json:"code"`
		Msg            string `json:"msg"`
		AppAccessToken string `json:"app_access_token"`
		Expire         int    `json:"expire"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return map[string]any{"status": "failed", "reason": "decode_failed", "http_status": resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || parsed.Code != 0 || strings.TrimSpace(parsed.AppAccessToken) == "" {
		return map[string]any{"status": "failed", "reason": "provider_rejected_credentials", "http_status": resp.StatusCode, "provider_code": parsed.Code, "provider_message": parsed.Msg}
	}
	return map[string]any{
		"status":               "ok",
		"mode":                 "live",
		"app_id":               appID,
		"app_token_expires_in": parsed.Expire,
		"can_login":            true,
		"checks": []map[string]any{
			{"key": "app_token", "ok": true, "label": "Feishu app_access_token"},
			{"key": "redirect_url", "ok": stringFromProviderConfig(config, "redirect_url") != "", "label": "Redirect URL configured locally"},
		},
	}
}

func stringFromProviderConfig(config map[string]any, key string) string {
	value, _ := config[key].(string)
	return strings.TrimSpace(value)
}

func boolFromProviderConfig(config map[string]any, key string) bool {
	value, _ := config[key].(bool)
	return value
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed))
		}
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
