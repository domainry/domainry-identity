package changeplans

import "net/http"

func (h *ChangePlansHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /tenant-admin/change-plans/validate", h.validate)
	mux.HandleFunc("GET /tenant-admin/change-plans/{planID}", h.getDraft)
	mux.HandleFunc("PUT /tenant-admin/change-plans/{planID}", h.saveDraft)
	mux.HandleFunc("POST /tenant-admin/change-plans/{planID}/review", h.review)
	mux.HandleFunc("POST /tenant-admin/change-plans/{planID}/approve", h.approve)
	mux.HandleFunc("POST /tenant-admin/change-plans/apply", h.apply)
}
