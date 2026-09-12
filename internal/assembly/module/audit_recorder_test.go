package moduleassembly

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/modulehttp"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
)

func TestModuleAuditRecorderAppendsIdentityOwnedDenial(t *testing.T) {
	var captured auditapplication.AuditAppendRequest
	recorder := moduleAuditRecorder{append: func(_ context.Context, request auditapplication.AuditAppendRequest) error {
		captured = request
		return nil
	}}
	err := recorder.Record(t.Context(), modulehttp.AuditEvent{
		Event: "auth_api_denied", ObjectKey: "identity.user_role_assignments", RecordID: "target-1",
		WorkspaceID: "workspace-a", ActorID: "coach-1", RoleKey: "coach", Summary: "Identity API permission denied",
		Metadata: map[string]any{"request_id": "request-1", "correlation_id": "correlation-1", "result": "denied", "reason": "permission_denied"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.IdempotencyKey != "auth_api_denied:request-1" || captured.Event != "auth_api_denied" || captured.ObjectKey != "identity.user_role_assignments" || captured.RecordID != "target-1" || captured.Principal.WorkspaceID != "workspace-a" || captured.Principal.UserID != "coach-1" || captured.Principal.Role.Key != "coach" || captured.Principal.RequestID != "request-1" || captured.Principal.CorrelationID != "correlation-1" {
		t.Fatalf("captured denial=%#v", captured)
	}
}
