package scimhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	scimapplication "github.com/domainry/domainry-identity/internal/application/scim"
	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

type routeRegistrar interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}

type Dependencies struct {
	Service      *scimapplication.Service
	BearerTokens map[string]string
	WritesFrozen func(context.Context, string) (bool, error)
	MaxBodyBytes int64
	Audit        func(*http.Request, string, string, map[string]any)
}

type Handler struct {
	service      *scimapplication.Service
	credentials  *credentialRegistry
	writesFrozen func(context.Context, string) (bool, error)
	maxBodyBytes int64
	audit        func(*http.Request, string, string, map[string]any)
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Service == nil {
		return nil, fmt.Errorf("SCIM service is required")
	}
	credentials, err := newCredentialRegistry(dependencies.BearerTokens)
	if err != nil {
		return nil, err
	}
	maxBodyBytes := dependencies.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = 2 << 20
	}
	return &Handler{service: dependencies.Service, credentials: credentials, writesFrozen: dependencies.WritesFrozen, maxBodyBytes: maxBodyBytes, audit: dependencies.Audit}, nil
}

func (h *Handler) RegisterRoutes(registrar routeRegistrar) {
	registrar.HandleFunc("GET /scim/v2/ServiceProviderConfig", h.authenticated(h.serviceProviderConfig))
	registrar.HandleFunc("GET /scim/v2/ResourceTypes", h.authenticated(h.resourceTypes))
	registrar.HandleFunc("GET /scim/v2/ResourceTypes/{resourceType}", h.authenticated(h.resourceType))
	registrar.HandleFunc("GET /scim/v2/Schemas", h.authenticated(h.schemas))
	registrar.HandleFunc("GET /scim/v2/Schemas/{schema}", h.authenticated(h.schema))
	registrar.HandleFunc("GET /scim/v2/Users", h.authenticated(h.listUsers))
	registrar.HandleFunc("POST /scim/v2/Users", h.authenticated(h.createUser))
	registrar.HandleFunc("GET /scim/v2/Users/{resourceID}", h.authenticated(h.getUser))
	registrar.HandleFunc("PUT /scim/v2/Users/{resourceID}", h.authenticated(h.replaceUser))
	registrar.HandleFunc("PATCH /scim/v2/Users/{resourceID}", h.authenticated(h.patchUser))
	registrar.HandleFunc("DELETE /scim/v2/Users/{resourceID}", h.authenticated(h.deleteUser))
	registrar.HandleFunc("GET /scim/v2/Groups", h.authenticated(h.listGroups))
	registrar.HandleFunc("POST /scim/v2/Groups", h.authenticated(h.createGroup))
	registrar.HandleFunc("GET /scim/v2/Groups/{resourceID}", h.authenticated(h.getGroup))
	registrar.HandleFunc("PUT /scim/v2/Groups/{resourceID}", h.authenticated(h.replaceGroup))
	registrar.HandleFunc("PATCH /scim/v2/Groups/{resourceID}", h.authenticated(h.patchGroup))
	registrar.HandleFunc("DELETE /scim/v2/Groups/{resourceID}", h.authenticated(h.deleteGroup))
}

func (h *Handler) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		workspaceID, ok := h.credentials.authorize(request.Header.Get("Authorization"))
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
			h.writeError(w, http.StatusUnauthorized, "", "A valid SCIM bearer token is required")
			return
		}
		ctx := requestcontext.WithWorkspaceID(request.Context(), workspaceID)
		request = request.WithContext(ctx)
		if request.Method != http.MethodGet && request.Method != http.MethodHead && h.writesFrozen != nil {
			frozen, err := h.writesFrozen(ctx, workspaceID)
			if err != nil {
				h.writeError(w, http.StatusServiceUnavailable, "", "SCIM provisioning is temporarily unavailable")
				return
			}
			if frozen {
				h.writeError(w, http.StatusLocked, "", "Workspace writes are frozen")
				return
			}
		}
		next(w, request)
	}
}

func (h *Handler) listUsers(w http.ResponseWriter, request *http.Request) {
	resources, err := h.service.ListUsers(request.Context(), request.URL.Query().Get("filter"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writePage(w, request, resources)
}

func (h *Handler) createUser(w http.ResponseWriter, request *http.Request) {
	var input scimmodel.User
	if !h.decode(w, request, &input) {
		return
	}
	resource, err := h.service.CreateUser(request.Context(), input)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_user_created", resource.ID, map[string]any{"external_id": resource.ExternalID})
	h.writeResource(w, request, http.StatusCreated, resource.Meta, resource)
}

func (h *Handler) getUser(w http.ResponseWriter, request *http.Request) {
	resource, err := h.service.GetUser(request.Context(), request.PathValue("resourceID"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeResource(w, request, http.StatusOK, resource.Meta, resource)
}

func (h *Handler) replaceUser(w http.ResponseWriter, request *http.Request) {
	var input scimmodel.User
	if !h.decode(w, request, &input) {
		return
	}
	resource, err := h.service.ReplaceUser(request.Context(), request.PathValue("resourceID"), input, request.Header.Get("If-Match"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_user_replaced", resource.ID, nil)
	h.writeResource(w, request, http.StatusOK, resource.Meta, resource)
}

func (h *Handler) patchUser(w http.ResponseWriter, request *http.Request) {
	var input scimmodel.PatchRequest
	if !h.decode(w, request, &input) {
		return
	}
	resource, err := h.service.PatchUser(request.Context(), request.PathValue("resourceID"), input, request.Header.Get("If-Match"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_user_patched", resource.ID, nil)
	h.writeResource(w, request, http.StatusOK, resource.Meta, resource)
}

func (h *Handler) deleteUser(w http.ResponseWriter, request *http.Request) {
	resourceID := request.PathValue("resourceID")
	if err := h.service.DeleteUser(request.Context(), resourceID, request.Header.Get("If-Match")); err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_user_deleted", resourceID, map[string]any{"identity_account_disabled": true, "sessions_revoked": true})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listGroups(w http.ResponseWriter, request *http.Request) {
	resources, err := h.service.ListGroups(request.Context(), request.URL.Query().Get("filter"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writePage(w, request, resources)
}

func (h *Handler) createGroup(w http.ResponseWriter, request *http.Request) {
	var input scimmodel.Group
	if !h.decode(w, request, &input) {
		return
	}
	resource, err := h.service.CreateGroup(request.Context(), input)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_group_created", resource.ID, map[string]any{"external_id": resource.ExternalID, "member_count": len(resource.Members)})
	h.writeResource(w, request, http.StatusCreated, resource.Meta, resource)
}

func (h *Handler) getGroup(w http.ResponseWriter, request *http.Request) {
	resource, err := h.service.GetGroup(request.Context(), request.PathValue("resourceID"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeResource(w, request, http.StatusOK, resource.Meta, resource)
}

func (h *Handler) replaceGroup(w http.ResponseWriter, request *http.Request) {
	var input scimmodel.Group
	if !h.decode(w, request, &input) {
		return
	}
	resource, err := h.service.ReplaceGroup(request.Context(), request.PathValue("resourceID"), input, request.Header.Get("If-Match"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_group_replaced", resource.ID, map[string]any{"member_count": len(resource.Members)})
	h.writeResource(w, request, http.StatusOK, resource.Meta, resource)
}

func (h *Handler) patchGroup(w http.ResponseWriter, request *http.Request) {
	var input scimmodel.PatchRequest
	if !h.decode(w, request, &input) {
		return
	}
	resource, err := h.service.PatchGroup(request.Context(), request.PathValue("resourceID"), input, request.Header.Get("If-Match"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_group_patched", resource.ID, map[string]any{"member_count": len(resource.Members)})
	h.writeResource(w, request, http.StatusOK, resource.Meta, resource)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, request *http.Request) {
	resourceID := request.PathValue("resourceID")
	if err := h.service.DeleteGroup(request.Context(), resourceID, request.Header.Get("If-Match")); err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.auditMutation(request, "scim_group_deleted", resourceID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writePage(w http.ResponseWriter, request *http.Request, resources any) {
	startIndex, count, err := listBounds(request)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	encoded, _ := json.Marshal(resources)
	var items []json.RawMessage
	if err := json.Unmarshal(encoded, &items); err != nil {
		h.writeError(w, http.StatusInternalServerError, "", "SCIM response could not be produced")
		return
	}
	total := len(items)
	start := startIndex - 1
	if start > total {
		start = total
	}
	end := start + count
	if end > total {
		end = total
	}
	page := items[start:end]
	for index := range page {
		projected, projectionErr := projectResponseAttributes(request, page[index])
		if projectionErr != nil {
			h.writeServiceError(w, projectionErr)
			return
		}
		page[index], _ = json.Marshal(projected)
	}
	h.writeJSON(w, http.StatusOK, scimmodel.ListResponse{Schemas: []string{scimmodel.SchemaListResponse}, TotalResults: total, StartIndex: startIndex, ItemsPerPage: len(page), Resources: page})
}

func listBounds(request *http.Request) (int, int, error) {
	startIndex, count := 1, 100
	if raw := strings.TrimSpace(request.URL.Query().Get("startIndex")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			return 0, 0, &scimapplication.Error{Status: 400, SCIMType: "invalidValue", Detail: "startIndex must be a positive integer"}
		}
		startIndex = parsed
	}
	if raw := strings.TrimSpace(request.URL.Query().Get("count")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return 0, 0, &scimapplication.Error{Status: 400, SCIMType: "invalidValue", Detail: "count must be a non-negative integer"}
		}
		count = parsed
	}
	if count > 1000 {
		count = 1000
	}
	return startIndex, count, nil
}

func (h *Handler) decode(w http.ResponseWriter, request *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, h.maxBodyBytes))
	if err := decoder.Decode(target); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalidSyntax", "Request body must contain valid SCIM JSON")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		h.writeError(w, http.StatusBadRequest, "invalidSyntax", "Request body must contain one JSON value")
		return false
	}
	return true
}

func (h *Handler) writeResource(w http.ResponseWriter, request *http.Request, status int, meta scimmodel.Meta, resource any) {
	if meta.Location != "" {
		w.Header().Set("Location", meta.Location)
		w.Header().Set("Content-Location", meta.Location)
	}
	if meta.Version != "" {
		w.Header().Set("ETag", meta.Version)
	}
	if request.Method == http.MethodGet {
		if etagHeaderMatches(request.Header.Get("If-None-Match"), meta.Version) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	projected, err := projectResponseAttributes(request, resource)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	h.writeJSON(w, status, projected)
}

func etagHeaderMatches(header, actual string) bool {
	if strings.TrimSpace(header) == "" || strings.TrimSpace(actual) == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == actual {
			return true
		}
	}
	return false
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	var scimErr *scimapplication.Error
	if errors.As(err, &scimErr) {
		h.writeError(w, scimErr.Status, scimErr.SCIMType, scimErr.Detail)
		return
	}
	status := http.StatusInternalServerError
	switch apperror.KindOf(err) {
	case apperror.KindBadRequest:
		status = http.StatusBadRequest
	case apperror.KindConflict:
		status = http.StatusConflict
	case apperror.KindNotFound:
		status = http.StatusNotFound
	case apperror.KindUnavailable:
		status = http.StatusServiceUnavailable
	}
	h.writeError(w, status, "", "SCIM request failed")
}

func (h *Handler) writeError(w http.ResponseWriter, status int, scimType, detail string) {
	response := map[string]any{"schemas": []string{scimmodel.SchemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		response["scimType"] = scimType
	}
	h.writeJSON(w, status, response)
}

func (h *Handler) auditMutation(request *http.Request, event, resourceID string, metadata map[string]any) {
	if h.audit == nil {
		return
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["resource_id"] = resourceID
	h.audit(request, event, "SCIM directory mutation", metadata)
}
