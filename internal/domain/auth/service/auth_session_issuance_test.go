package service

import (
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestSessionIssuance(t *testing.T) {
	fault := errors.New("session issuance fault")
	user := activeExternalIdentityUser("user", "user@example.com")

	t.Run("role lookup failure", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listAssignmentsErr = fault
		_, err := auth.issueSession(t.Context(), "workspace-primary", user)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("reconciles profile roles before role lookup", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.reconcileErr = fault
		_, err := auth.issueSession(t.Context(), "workspace-primary", user)
		assertExternalAuthFault(t, err, fault)
		if identityRepository.reconcileCalls.Load() != 1 {
			t.Fatalf("reconcile calls=%d", identityRepository.reconcileCalls.Load())
		}
	})

	t.Run("refresh token write failure", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.createRefreshTokenErr = fault
		_, err := auth.issueSession(t.Context(), "workspace-primary", user)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("permission lookup failure", func(t *testing.T) {
		auth, _, _ := newFaultAuthDomainService()
		auth.authorization = &faultSessionAuthorization{permissionsErr: fault}
		_, err := auth.issueSession(t.Context(), "workspace-primary", user)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("success with active roles", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.roleAssignments = []identitymodel.IdentityUserRoleAssignment{{UserID: user.ID, RoleID: "role-sales"}}
		auth.authorization = &faultSessionAuthorization{
			permissions: []string{"runtime.operations.list_operations", "identity.users.list"},
		}
		authRepository.credentials = map[string]identitymodel.IdentityCredential{
			user.ID: {UserID: user.ID, MustChangePassword: true},
		}
		session, err := auth.issueSession(t.Context(), "workspace-primary", user)
		if err != nil {
			t.Fatalf("issue session: %v", err)
		}
		if session.AccessToken == "" || session.RefreshToken == "" || session.DefaultRole != "sales" || !session.MustChangePassword ||
			len(session.Permissions) != 2 || len(authRepository.refreshTokens) != 1 {
			t.Fatalf("unexpected issued session: %#v", session)
		}
	})
}
