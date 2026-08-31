package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type httpSupport struct {
	auth                   *authapplication.AuthApplicationService
	corsAllowedOrigins     map[string]struct{}
	corsAllowAnyOrigin     bool
	request                atomic.Uint64
	writesFrozen           func(context.Context, string) (bool, error)
	controls               *httpSurfaceControls
	initializedWorkspaceID string
}

func newHTTPSupport(auth *authapplication.AuthApplicationService, allowedOrigins []string, controlConfig ...httpControlConfig) *httpSupport {
	support := &httpSupport{auth: auth, corsAllowedOrigins: make(map[string]struct{}, len(allowedOrigins))}
	if len(controlConfig) > 0 {
		support.controls = newHTTPSurfaceControls(controlConfig[0])
	}
	for _, origin := range allowedOrigins {
		origin = strings.TrimRight(strings.TrimSpace(origin), "/")
		if origin == "*" {
			support.corsAllowAnyOrigin = true
			continue
		}
		if origin != "" {
			support.corsAllowedOrigins[origin] = struct{}{}
		}
	}
	return support
}

func (h *httpSupport) corsOriginAllowed(origin string) bool {
	origin = strings.TrimRight(strings.TrimSpace(origin), "/")
	if origin == "" || h == nil {
		return false
	}
	if h.corsAllowAnyOrigin {
		return true
	}
	_, allowed := h.corsAllowedOrigins[origin]
	return allowed
}

func (h *httpSupport) principal(r *http.Request) identitymodel.Principal {
	if h == nil || h.auth == nil {
		return identitymodel.Principal{}
	}
	principal, err := h.auth.PrincipalFromBearer(r.Context(), r.Header.Get("Authorization"), requestcontext.RequestID(r.Context()))
	if err != nil {
		return identitymodel.Principal{}
	}
	return principal
}

func (h *httpSupport) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func (h *httpSupport) writeError(w http.ResponseWriter, _ *http.Request, status int, code string, params ...string) {
	details := map[string]string{}
	for index := 0; index+1 < len(params); index += 2 {
		details[params[index]] = params[index+1]
	}
	payload := map[string]any{"code": code, "error": map[string]any{"code": code}}
	if len(details) > 0 {
		payload["params"] = details
		payload["error"].(map[string]any)["params"] = details
	}
	h.writeJSON(w, status, payload)
}

func (h *httpSupport) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var sdkError *identitysdk.Error
	if errors.As(err, &sdkError) {
		status := sdkError.StatusCode
		if status == 0 {
			status = http.StatusBadRequest
		}
		params := []string{}
		for key, value := range sdkError.Params {
			params = append(params, key, value)
		}
		h.writeError(w, r, status, sdkError.Code, params...)
		return
	}
	status := http.StatusInternalServerError
	switch apperror.KindOf(err) {
	case apperror.KindBadRequest:
		status = http.StatusBadRequest
	case apperror.KindForbidden:
		status = http.StatusForbidden
	case apperror.KindNotFound:
		status = http.StatusNotFound
	case apperror.KindConflict:
		status = http.StatusConflict
	case apperror.KindRateLimited:
		status = http.StatusTooManyRequests
	case apperror.KindUnavailable:
		status = http.StatusServiceUnavailable
	}
	params := []string{}
	for key, value := range apperror.ParamsOf(err) {
		params = append(params, key, value)
	}
	h.writeError(w, r, status, apperror.CodeOf(err), params...)
}

func (h *httpSupport) decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	limit := int64(4 << 20)
	if h != nil && h.controls != nil {
		limit = h.controls.bodyLimit(classifyRouteSurface(r.Method, r.URL.Path))
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		h.writeError(w, r, http.StatusBadRequest, "backend.invalid_json")
		return false
	}
	return true
}

func (h *httpSupport) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.principal(r).Known {
			h.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		next(w, r)
	}
}

func (h *httpSupport) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := h.principal(r)
		if !principal.Known || !hasPermission(principal.Role.Permissions, "workspace.admin") {
			h.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next(w, r)
	}
}

func hasPermission(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func (h *httpSupport) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if h.corsOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, Builder-Task-ID, Expected-Schema-Hash, X-Request-ID, X-Workspace-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = "identity-" + time.Now().UTC().Format("20060102T150405.000000000")
		}
		workspaceID := strings.TrimSpace(r.Header.Get("X-Workspace-ID"))
		if workspaceID == "" {
			workspaceID = strings.TrimSpace(h.initializedWorkspaceID)
		}
		if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
			h.writeError(w, r, http.StatusBadRequest, "backend.workspace_scope_required")
			return
		}
		ctx := requestcontext.WithRequestID(r.Context(), requestID)
		ctx = requestcontext.WithWorkspaceID(ctx, workspaceID)
		surface := classifyRouteSurface(r.Method, r.URL.Path)
		if h.controls != nil {
			allowed, remaining, resetAt := h.controls.allow(surface)
			if !resetAt.IsZero() {
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
			}
			if !allowed {
				retryAfter := int(time.Until(resetAt).Seconds()) + 1
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				h.writeError(w, r, http.StatusTooManyRequests, "identity.http_rate_limited", "surface", string(surface))
				return
			}
			if timeout := h.controls.timeout(surface); timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
		}
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", requestID)
		if h.mustRejectFrozenWrite(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *httpSupport) mustRejectFrozenWrite(w http.ResponseWriter, request *http.Request) bool {
	if h == nil || h.writesFrozen == nil || request == nil {
		return false
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	if strings.HasPrefix(request.URL.Path, "/ops/identity-portability/") {
		return false
	}
	workspaceID := requestcontext.WorkspaceID(request.Context())
	if principal := h.principal(request); principal.Known && strings.TrimSpace(principal.WorkspaceID) != "" {
		workspaceID = strings.TrimSpace(principal.WorkspaceID)
	}
	frozen, err := h.writesFrozen(request.Context(), workspaceID)
	if err != nil {
		h.writeError(w, request, http.StatusServiceUnavailable, "identity.write_fence_unavailable")
		return true
	}
	if frozen {
		h.writeError(w, request, http.StatusLocked, "identity.workspace_writes_frozen")
		return true
	}
	return false
}

func ignoreAudit(*http.Request, string, string, ...map[string]any) {}

func isServerClosed(err error) bool {
	return err == nil || errors.Is(err, http.ErrServerClosed)
}
