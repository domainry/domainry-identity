package portabilityhttp

import (
	"crypto/subtle"
	"net/http"
	"strings"

	portabilityapplication "github.com/domainry/domainry-identity/internal/application/portability"
	portabilitymodel "github.com/domainry/domainry-identity/internal/domain/portability"
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
	registrar.HandleFunc("POST /ops/identity-portability/write-fences", handler.authorize(handler.freezeWrites))
	registrar.HandleFunc("POST /ops/identity-portability/write-fences/{workspaceID}/release", handler.authorize(handler.releaseWriteFence))
	registrar.HandleFunc("POST /ops/identity-portability/exports", handler.authorize(handler.export))
	registrar.HandleFunc("POST /ops/identity-portability/imports", handler.authorize(handler.importBundle))
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

type exportRequest struct {
	WorkspaceID    string `json:"workspace_id"`
	SourceMode     string `json:"source_mode"`
	FreezeEvidence string `json:"freeze_evidence,omitempty"`
	DryRun         bool   `json:"dry_run"`
}

func (handler *Handler) export(w http.ResponseWriter, request *http.Request) {
	var input exportRequest
	if !handler.dependencies.DecodeJSON(w, request, &input) {
		return
	}
	result, err := handler.dependencies.Service.Export(request.Context(), portabilityapplication.ExportRequest{
		WorkspaceID: input.WorkspaceID, SourceMode: input.SourceMode, FreezeEvidence: input.FreezeEvidence, DryRun: input.DryRun,
	})
	if err != nil {
		handler.writeOperationError(w, request, err)
		return
	}
	handler.dependencies.WriteJSON(w, http.StatusOK, result)
}

type importRequest struct {
	Bundle                  portabilitymodel.Bundle `json:"bundle"`
	IdempotencyKey          string                  `json:"idempotency_key"`
	DryRun                  bool                    `json:"dry_run"`
	ProviderReadiness       map[string]bool         `json:"provider_readiness"`
	AcceptSessionRevocation bool                    `json:"accept_session_revocation"`
	AcceptCredentialReset   bool                    `json:"accept_credential_reset"`
	AcceptMFAReenrollment   bool                    `json:"accept_mfa_reenrollment"`
}

func (handler *Handler) importBundle(w http.ResponseWriter, request *http.Request) {
	var input importRequest
	if !handler.dependencies.DecodeJSON(w, request, &input) {
		return
	}
	result, err := handler.dependencies.Service.Import(request.Context(), portabilityapplication.ImportRequest{
		Bundle: input.Bundle, IdempotencyKey: input.IdempotencyKey, DryRun: input.DryRun,
		ProviderReadiness: input.ProviderReadiness, AcceptSessionRevocation: input.AcceptSessionRevocation,
		AcceptCredentialReset: input.AcceptCredentialReset, AcceptMFAReenrollment: input.AcceptMFAReenrollment,
	})
	if err != nil {
		handler.writeOperationError(w, request, err)
		return
	}
	handler.dependencies.WriteJSON(w, http.StatusOK, result)
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
