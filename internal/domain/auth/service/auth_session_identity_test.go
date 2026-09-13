package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"errors"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestCurrentSessionIdentity(t *testing.T) {
	fault := errors.New("current session identity fault")

	t.Run("invalid access token", func(t *testing.T) {
		auth, _, _ := newFaultAuthDomainService()
		if _, err := auth.Me(t.Context(), "invalid"); err == nil {
			t.Fatal("expected invalid access token")
		}
	})

	t.Run("identity lookup failure", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listUsersErr = fault
		_, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, "user", "workspace-primary"))
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("identity missing", func(t *testing.T) {
		auth, _, _ := newFaultAuthDomainService()
		if _, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, "missing", "workspace-primary")); err == nil {
			t.Fatal("expected missing session identity")
		}
	})

	t.Run("identity disabled", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		user := activeExternalIdentityUser("user", "user@example.com")
		user.Status = identitymodel.IdentityStatusDisabled
		identityRepository.users = []identitymodel.IdentityUser{user}
		if _, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, user.ID, "workspace-primary")); err == nil {
			t.Fatal("expected disabled session identity")
		}
	})

	t.Run("role lookup failure", func(t *testing.T) {
		auth, identityRepository, _ := currentIdentityFixture()
		identityRepository.listAssignmentsErr = fault
		_, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, "user", "workspace-primary"))
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("permission lookup failure", func(t *testing.T) {
		auth, _, authorization := currentIdentityFixture()
		authorization.permissionsErr = fault
		_, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, "user", "workspace-primary"))
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("credential handoff lookup failure", func(t *testing.T) {
		auth, _, _ := currentIdentityFixture()
		fault := errors.New("credential handoff lookup")
		auth.identityStore.(*faultExternalAuthRepository).getCredentialErr = fault
		_, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, "user", "workspace-primary"))
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("success", func(t *testing.T) {
		auth, _, authorization := currentIdentityFixture()
		authRepository := auth.identityStore.(*faultExternalAuthRepository)
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": {
			UserID:             "user",
			MustChangePassword: true,
		}}
		authorization.permissions = []string{
			"identity.users.list",
			"runtime.operations.list_operations",
		}
		response, err := auth.Me(t.Context(), validIdentityAccessToken(t, auth, "user", "workspace-primary"))
		if err != nil {
			t.Fatalf("resolve current session identity: %v", err)
		}
		if response.User.ID != "user" || response.User.Locale != "en-US" || response.User.Version != 1 || response.DefaultRole != "sales" || !response.MustChangePassword || len(response.Permissions) != 2 {
			t.Fatalf("unexpected current identity: %#v", response)
		}
	})
}

func TestIssueSessionForUserCoversLookupStatusAndCredentialFailures(t *testing.T) {
	fault := errors.New("session user lookup")
	auth, identities, repository := newFaultAuthDomainService()
	identities.listUsersErr = fault
	if _, err := auth.IssueSessionForUser(t.Context(), "workspace", "user"); !errors.Is(err, fault) {
		t.Fatalf("lookup error=%v", err)
	}
	identities.listUsersErr = nil
	if _, err := auth.IssueSessionForUser(t.Context(), "workspace", "missing"); err == nil {
		t.Fatal("missing user session issued")
	}
	user := activeExternalIdentityUser("user", "user@example.com")
	user.Status = identitymodel.IdentityStatusDisabled
	identities.users = []identitymodel.IdentityUser{user}
	if _, err := auth.IssueSessionForUser(t.Context(), "workspace", user.ID); err == nil {
		t.Fatal("disabled user session issued")
	}
	user.Status = identitymodel.IdentityStatusActive
	identities.users = []identitymodel.IdentityUser{user}
	repository.getCredentialErr = errors.New("credential")
	if _, err := auth.IssueSessionForUser(t.Context(), "workspace", user.ID); !errors.Is(err, repository.getCredentialErr) {
		t.Fatalf("credential error=%v", err)
	}
}

func TestPrincipalFromBearerToken(t *testing.T) {
	fault := errors.New("principal resolution fault")
	auth, _, authorization := currentIdentityFixture()

	if _, err := auth.PrincipalFromBearer(t.Context(), "Basic credentials", "request"); err == nil {
		t.Fatal("expected missing bearer token")
	}
	if _, err := auth.PrincipalFromBearer(t.Context(), "Bearer invalid", "request"); err == nil {
		t.Fatal("expected invalid bearer token")
	}
	authorization.principalErr = fault
	_, err := auth.PrincipalFromBearer(t.Context(), "Bearer "+validIdentityAccessToken(t, auth, "user", "workspace-primary"), "request")
	assertExternalAuthFault(t, err, fault)
	authorization.principalErr = nil

	principal, err := auth.PrincipalFromBearer(t.Context(), "Bearer "+validIdentityAccessToken(t, auth, "user", "workspace-a"), "request-a")
	if err != nil || principal.WorkspaceID != "workspace-a" || principal.RequestID != "request-a" {
		t.Fatalf("resolve principal with workspace: principal=%#v err=%v", principal, err)
	}
	principal, err = auth.PrincipalFromBearer(t.Context(), "Bearer "+validIdentityAccessToken(t, auth, "user", ""), "request-b")
	if err == nil || principal.Known {
		t.Fatalf("missing initialized workspace was accepted: principal=%#v err=%v", principal, err)
	}
}

func currentIdentityFixture() (*AuthDomainService, *faultExternalIdentityRepository, *faultSessionAuthorization) {
	auth, identityRepository, _ := newFaultAuthDomainService()
	identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", "user@example.com")}
	identityRepository.roleAssignments = []identitymodel.IdentityUserRoleAssignment{{UserID: "user", RoleID: "role-sales"}}
	authorization := &faultSessionAuthorization{
		principal:   identitymodel.Principal{UserID: "user", Known: true},
		permissions: []string{"record.read"},
	}
	auth.authorization = authorization
	return auth, identityRepository, authorization
}

func validIdentityAccessToken(t *testing.T, auth *AuthDomainService, userID string, workspaceID string) string {
	t.Helper()
	repository := auth.identityStore.(*faultExternalAuthRepository)
	repository.refreshTokens = append(repository.refreshTokens, identitymodel.AuthRefreshToken{UserID: userID, SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	return mustSignClaims(t, auth, authmodel.AuthClaims{Subject: userID, WorkspaceID: workspaceID, SessionID: "session", ExpiresAt: time.Now().Add(time.Hour).Unix()})
}

type faultSessionAuthorization struct {
	principal      identitymodel.Principal
	permissions    []string
	principalErr   error
	permissionsErr error
}

func (a *faultSessionAuthorization) ResolvePrincipal(context.Context, string) (identitymodel.Principal, error) {
	return a.principal, a.principalErr
}

func (a *faultSessionAuthorization) ResolvePrincipalForRole(context.Context, string, string) (identitymodel.Principal, error) {
	return a.principal, a.principalErr
}

func (a *faultSessionAuthorization) ResolveEffectivePermissions(context.Context, string) ([]string, error) {
	return append([]string(nil), a.permissions...), a.permissionsErr
}

func (a *faultSessionAuthorization) ResolveEffectiveMenus(context.Context, string) ([]identitymodel.IdentityMenu, error) {
	return nil, nil
}
