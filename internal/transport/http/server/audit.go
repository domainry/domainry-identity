package httpserver

import (
	"net/http"
	"strconv"
	"strings"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	auditapplication "github.com/domainry/domainry-identity/internal/application/audit"
)

func registerAuditRoutes(mux *http.ServeMux, audit *auditapplication.AuditApplicationService, support *httpSupport) {
	mux.HandleFunc("GET /tenant-admin/audit-events", support.admin(func(w http.ResponseWriter, r *http.Request) {
		result, err := audit.TenantGovernanceEvents(r.Context(), auditEventQuery(r), support.principal(r))
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, result)
	}))
	mux.HandleFunc("GET /tenant-admin/audit-events/export", support.admin(func(w http.ResponseWriter, r *http.Request) {
		result, err := audit.TenantGovernanceExport(r.Context(), auditEventQuery(r), support.principal(r))
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="tenant-governance-audit.json"`)
		support.writeJSON(w, http.StatusOK, result)
	}))
}

func auditEventQuery(r *http.Request) auditmodel.AuditEventQuery {
	values := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(values.Get("page_size")))
	if limit == 0 {
		limit, _ = strconv.Atoi(strings.TrimSpace(values.Get("limit")))
	}
	return auditmodel.AuditEventQuery{
		ObjectKey: strings.TrimSpace(values.Get("object_key")), RecordID: strings.TrimSpace(values.Get("record_id")),
		Event: strings.TrimSpace(values.Get("event")), ActorID: strings.TrimSpace(values.Get("actor_id")),
		RoleKey: strings.TrimSpace(values.Get("role_key")), RequestID: strings.TrimSpace(values.Get("request_id")),
		CreatedFrom: strings.TrimSpace(values.Get("created_from")), CreatedTo: strings.TrimSpace(values.Get("created_to")),
		Limit: limit, Cursor: strings.TrimSpace(values.Get("cursor")),
	}
}
