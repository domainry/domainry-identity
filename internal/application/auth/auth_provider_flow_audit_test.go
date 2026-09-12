package auth

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestProviderAuthenticationAuditUsesStableTraceAndSafeFields(t *testing.T) {
	service := NewAuthProviderFlowApplicationService(nil, nil)
	requests := make([]AuthenticationAuditRequest, 0, 2)
	service.ConfigureAuthenticationAudit(func(_ context.Context, request AuthenticationAuditRequest) error {
		requests = append(requests, request)
		return nil
	})

	successContext := requestcontext.WithRequestID(t.Context(), "provider-success-request")
	err := service.appendAuthenticationSuccess(successContext, "provider", "oidc", "member-app", authmodel.AuthSession{
		WorkspaceID: "workspace-1", User: authmodel.AuthUser{ID: "user-1"}, DefaultRole: "member",
	})
	if err != nil {
		t.Fatal(err)
	}
	failureContext := requestcontext.WithRequestID(t.Context(), "provider-failure-request")
	if err := service.appendAuthenticationFailure(failureContext, "workspace-1", "provider", "oidc", "member-app", "", "authentication_failed", "auth.provider_state_invalid"); err != nil {
		t.Fatal(err)
	}

	if len(requests) != 2 {
		t.Fatalf("audit requests=%d", len(requests))
	}
	succeeded, failed := requests[0], requests[1]
	if succeeded.Event != "auth_login_succeeded" || succeeded.IdempotencyKey != "auth_login_succeeded:provider-success-request" || succeeded.Principal.UserID != "user-1" || succeeded.Principal.Role.Key != "member" || succeeded.Metadata["authentication_method"] != "provider" || succeeded.Metadata["provider"] != "oidc" || succeeded.Metadata["application_key"] != "member-app" || succeeded.Metadata["result"] != "success" || succeeded.Metadata["reason"] != "authentication_completed" {
		t.Fatalf("provider success audit=%#v", succeeded)
	}
	if failed.Event != "auth_login_failed" || failed.IdempotencyKey != "auth_login_failed:provider-failure-request" || failed.Principal.Known || failed.Principal.UserID != "anonymous" || failed.Principal.Role.Key != "anonymous" || failed.Metadata["result"] != "failed" || failed.Metadata["reason"] != "authentication_failed" || failed.Metadata["error_code"] != "auth.provider_state_invalid" {
		t.Fatalf("provider failure audit=%#v", failed)
	}
	for _, forbidden := range []string{"password", "token", "login", "code", "state"} {
		if _, found := failed.Metadata[forbidden]; found {
			t.Fatalf("provider failure audit exposes %s", forbidden)
		}
	}
}
