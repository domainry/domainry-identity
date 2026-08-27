package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthHandlerRequiresExplicitWorkspace(t *testing.T) {
	writtenCode := ""
	handler := NewAuthHandler(AuthDependencies{
		WriteError: func(_ http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
			if status != http.StatusBadRequest {
				t.Fatalf("status=%d", status)
			}
			writtenCode = code
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	if workspaceID, ok := handler.requireWorkspace(httptest.NewRecorder(), request, ""); ok || workspaceID != "" {
		t.Fatalf("missing workspace accepted: workspace=%q ok=%v", workspaceID, ok)
	}
	if writtenCode != "backend.workspace_scope_required" {
		t.Fatalf("error code=%q", writtenCode)
	}
	if workspaceID, ok := handler.requireWorkspace(httptest.NewRecorder(), request, " workspace-a "); !ok || workspaceID != "workspace-a" {
		t.Fatalf("valid workspace rejected: workspace=%q ok=%v", workspaceID, ok)
	}
}

func TestAuthHandlerRejectsPublicMutationsForFrozenBodyWorkspace(t *testing.T) {
	writtenStatus, writtenCode := 0, ""
	handler := NewAuthHandler(AuthDependencies{
		WritesFrozen: func(_ context.Context, workspaceID string) (bool, error) {
			return workspaceID == "workspace-a", nil
		},
		WriteError: func(_ http.ResponseWriter, _ *http.Request, status int, code string, _ ...string) {
			writtenStatus, writtenCode = status, code
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	if workspaceID, ok := handler.requireWorkspace(httptest.NewRecorder(), request, "workspace-a"); ok || workspaceID != "" {
		t.Fatalf("frozen workspace accepted: workspace=%q ok=%v", workspaceID, ok)
	}
	if writtenStatus != http.StatusLocked || writtenCode != "identity.workspace_writes_frozen" {
		t.Fatalf("status=%d code=%q", writtenStatus, writtenCode)
	}
}
