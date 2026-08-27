package service

import (
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestGuestSessionRoleResolutionAndIssuance(t *testing.T) {
	t.Run("default role", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "role-customer", Key: "customer", Label: "Customer", Status: identitymodel.IdentityStatusActive})
		session, err := auth.GuestSession(t.Context(), "default", " ")
		if err != nil {
			t.Fatalf("issue default guest session: %v", err)
		}
		if session.User.ID != "guest_customer" || session.AccessToken == "" {
			t.Fatalf("unexpected guest session: %#v", session)
		}
	})

	t.Run("role id", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "guest-role-id", Key: "customer", Label: "Customer", Status: identitymodel.IdentityStatusActive})
		if _, err := auth.GuestSession(t.Context(), "default", "guest-role-id"); err != nil {
			t.Fatalf("issue guest session by role id: %v", err)
		}
	})

	t.Run("unavailable role", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = []identitymodel.IdentityRole{{ID: "disabled", Key: "customer", Status: identitymodel.IdentityStatusDisabled}}
		if _, err := auth.GuestSession(t.Context(), "default", "missing"); err == nil {
			t.Fatal("expected unavailable guest role")
		}
	})
}

func TestGuestSessionPropagatesDomainFailures(t *testing.T) {
	fault := errors.New("guest session fault")

	t.Run("role listing", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listRolesErr = fault
		_, err := auth.GuestSession(t.Context(), "default", "sales")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("guest user write", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.upsertUserErr = fault
		_, err := auth.GuestSession(t.Context(), "default", "sales")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("role assignment", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.assignRoleErr = fault
		_, err := auth.GuestSession(t.Context(), "default", "sales")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("session issuance", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listAssignmentsErr = fault
		_, err := auth.GuestSession(t.Context(), "default", "sales")
		assertExternalAuthFault(t, err, fault)
	})
}
