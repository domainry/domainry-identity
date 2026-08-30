package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPMiddlewareRejectsIdentityMutationsWhileWorkspaceIsFrozen(t *testing.T) {
	support := newHTTPSupport(nil, nil)
	support.writesFrozen = func(_ context.Context, workspaceID string) (bool, error) {
		return workspaceID == "workspace-a", nil
	}
	calls := 0
	handler := support.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	mutation := httptest.NewRequest(http.MethodPost, "/identity/users", nil)
	mutation.Header.Set("X-Workspace-ID", "workspace-a")
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, mutation)
	if blocked.Code != http.StatusLocked || calls != 0 {
		t.Fatalf("blocked status=%d calls=%d body=%s", blocked.Code, calls, blocked.Body.String())
	}

	read := httptest.NewRequest(http.MethodGet, "/identity/users", nil)
	read.Header.Set("X-Workspace-ID", "workspace-a")
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, read)
	if allowed.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("read status=%d calls=%d", allowed.Code, calls)
	}

	operation := httptest.NewRequest(http.MethodPost, "/ops/identity-portability/write-fences", nil)
	operation.Header.Set("X-Workspace-ID", "workspace-a")
	ops := httptest.NewRecorder()
	handler.ServeHTTP(ops, operation)
	if ops.Code != http.StatusNoContent || calls != 2 {
		t.Fatalf("operation status=%d calls=%d", ops.Code, calls)
	}
}
