package service

import (
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
)

func TestApplicationServiceTokenIsShortLivedScopedAndNotAUserSession(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	if err := auth.ConfigureTokenMetadata("https://identity.example", "unused-default"); err != nil {
		t.Fatal(err)
	}
	token, expiresAt, revision, err := auth.IssueApplicationServiceToken(t.Context(), "workspace-a", "orders-runtime", "domainry-notification", "blue", []authmodel.AuthServiceGrant{{Resource: "notification_event", Action: "publish"}})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || revision == "" || time.Until(expiresAt) <= 0 || time.Until(expiresAt) > applicationServiceTokenTTL+time.Second {
		t.Fatalf("token=%q expires=%v revision=%q", token, expiresAt, revision)
	}
	claims, err := auth.VerifyApplicationServiceToken(t.Context(), token, "domainry-notification", "notification_event", "publish")
	if err != nil || claims.Subject != "service:orders-runtime" || claims.ServiceCredentialID != "blue" || claims.WorkspaceID != "workspace-a" {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	if _, err := auth.VerifyApplicationServiceToken(t.Context(), token, "other-service", "notification_event", "publish"); apperror.CodeOf(err) != "identity.application_service_token_invalid" {
		t.Fatalf("audience mismatch error=%v", err)
	}
	if _, err := auth.VerifyApplicationServiceToken(t.Context(), token, "domainry-notification", "notification_governance", "read"); apperror.CodeOf(err) != "identity.application_service_grant_denied" {
		t.Fatalf("grant mismatch error=%v", err)
	}
	if _, err := auth.VerifyAccessToken(t.Context(), token); apperror.CodeOf(err) != "auth.user_token_required" {
		t.Fatalf("service token accepted as user session: %v", err)
	}
}
