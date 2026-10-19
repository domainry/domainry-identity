package auth

import (
	"io"
	"net/http"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (h *AuthHandler) feishuEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.feishuEventPolicy.Ready() {
		h.writeError(w, r, http.StatusServiceUnavailable, "auth.feishu_offboarding_unavailable")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		h.writeError(w, r, http.StatusBadRequest, "auth.feishu_event_invalid")
		return
	}
	event, err := h.feishuEventPolicy.Verify(body, r.Header, time.Now())
	if err != nil {
		h.writeError(w, r, http.StatusForbidden, "auth.feishu_event_invalid")
		return
	}
	if event.Type == "url_verification" {
		h.writeJSON(w, http.StatusOK, map[string]string{"challenge": event.Challenge})
		return
	}
	if event.Header.EventType != "contact.user.deleted_v3" {
		h.writeJSON(w, http.StatusOK, map[string]int{"code": 0})
		return
	}
	if !h.requireMutableWorkspace(w, r, h.feishuEventPolicy.WorkspaceID) {
		return
	}
	userID, err := h.feishuOffboarding.Archive(r.Context(), event.Event.Object.UnionID)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	if userID != "" && h.securityAuditForPrincipal != nil {
		h.securityAuditForPrincipal(r, identitymodel.Principal{WorkspaceID: h.feishuEventPolicy.WorkspaceID, UserID: "feishu-offboarding"}, "identity_user_offboarded", "Archived departed Feishu account; business history retained", map[string]any{"user_id": userID, "provider_event_id": event.Header.EventID})
	}
	h.writeJSON(w, http.StatusOK, map[string]int{"code": 0})
}
