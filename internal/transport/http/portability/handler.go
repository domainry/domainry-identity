package portabilityhttp

import (
	"crypto/subtle"
	"net/http"
	"strings"

	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
)

type RouteRegistrar interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}

type Dependencies struct {
	Service     *portabilityapplication.Service
	AccessToken string
	DecodeJSON  func(http.ResponseWriter, *http.Request, any) bool
	WriteJSON   func(http.ResponseWriter, int, any)
	WriteError  func(http.ResponseWriter, *http.Request, int, string, ...string)
}

type Handler struct {
	dependencies Dependencies
}

func NewHandler(dependencies Dependencies) *Handler {
	return &Handler{dependencies: dependencies}
}

func (handler *Handler) RegisterRoutes(registrar RouteRegistrar) {
	registrar.HandleFunc("POST /identity/portability/write-fences", handler.authorize(handler.freezeWrites))
	registrar.HandleFunc("POST /identity/portability/write-fences/{workspaceID}/release", handler.authorize(handler.releaseWriteFence))
}

type freezeRequest struct {
	WorkspaceID string `json:"workspace_id"`
	Evidence    string `json:"evidence"`
	Operator    string `json:"operator"`
}

func (handler *Handler) freezeWrites(w http.ResponseWriter, request *http.Request) {
	var input freezeRequest
	if !handler.dependencies.DecodeJSON(w, request, &input) {
		return
	}
	fence, err := handler.dependencies.Service.FreezeWrites(request.Context(), input.WorkspaceID, input.Evidence, input.Operator)
	if err != nil {
		handler.writeOperationError(w, request, err)
		return
	}
	handler.dependencies.WriteJSON(w, http.StatusOK, fence)
}

type releaseRequest struct {
	Operator string `json:"operator"`
}

func (handler *Handler) releaseWriteFence(w http.ResponseWriter, request *http.Request) {
	var input releaseRequest
	if !handler.dependencies.DecodeJSON(w, request, &input) {
		return
	}
	fence, err := handler.dependencies.Service.ReleaseWriteFence(request.Context(), request.PathValue("workspaceID"), input.Operator)
	if err != nil {
		handler.writeOperationError(w, request, err)
		return
	}
	handler.dependencies.WriteJSON(w, http.StatusOK, fence)
}

func (handler *Handler) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		expected := strings.TrimSpace(handler.dependencies.AccessToken)
		if expected == "" || handler.dependencies.Service == nil {
			handler.dependencies.WriteError(w, request, http.StatusServiceUnavailable, "identity.operations_not_configured")
			return
		}
		provided := strings.TrimSpace(request.Header.Get("Authorization"))
		provided, found := strings.CutPrefix(provided, "Bearer ")
		if !found || len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			handler.dependencies.WriteError(w, request, http.StatusUnauthorized, "identity.operations_token_invalid")
			return
		}
		next(w, request)
	}
}

func (handler *Handler) writeOperationError(w http.ResponseWriter, request *http.Request, err error) {
	code := strings.TrimSpace(err.Error())
	if prefix, _, found := strings.Cut(code, ":"); found {
		code = strings.TrimSpace(prefix)
	}
	status := http.StatusBadRequest
	for _, conflict := range []string{
		"target_not_empty", "idempotency_conflict", "write_fence_already_active", "write_fence_not_active",
		"metadata_schema_mismatch", "authorization_parity_failed", "provider_not_ready", "provider_configuration_mismatch",
	} {
		if strings.Contains(code, conflict) {
			status = http.StatusConflict
			break
		}
	}
	if !strings.HasPrefix(code, "identity.portability_") {
		code = "identity.portability_operation_failed"
		status = http.StatusInternalServerError
	}
	handler.dependencies.WriteError(w, request, status, code)
}
