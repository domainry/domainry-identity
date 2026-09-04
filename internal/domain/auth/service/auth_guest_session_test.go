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
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer", RiskLevel: identitymodel.IdentityRoleRiskNormal}
		session, err := auth.GuestSession(t.Context(), "workspace-primary", " ")
		if err != nil {
			t.Fatalf("issue default guest session: %v", err)
		}
		if session.User.ID != "guest_customer" || session.AccessToken == "" {
			t.Fatalf("unexpected guest session: %#v", session)
		}
	})

	t.Run("caller cannot select role", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "guest-role-id", Key: "customer", Label: "Customer", Status: identitymodel.IdentityStatusActive})
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer", RiskLevel: identitymodel.IdentityRoleRiskNormal}
		session, err := auth.GuestSession(t.Context(), "workspace-primary", "admin")
		if err != nil || len(session.Roles) != 1 || session.Roles[0].Key != "customer" {
			t.Fatalf("anonymous role selection changed guest authority: session=%#v err=%v", session, err)
		}
	})

	t.Run("unavailable role", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = []identitymodel.IdentityRole{{ID: "disabled", Key: "customer", Status: identitymodel.IdentityStatusDisabled}}
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer"}
		if _, err := auth.GuestSession(t.Context(), "workspace-primary", "missing"); err == nil {
			t.Fatal("expected unavailable guest role")
		}
	})

	t.Run("privileged guest role is rejected", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "role-customer", Key: "customer", Status: identitymodel.IdentityStatusActive})
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer", RiskLevel: identitymodel.IdentityRoleRiskPrivileged}
		if _, err := auth.GuestSession(t.Context(), "workspace-primary", "customer"); err == nil {
			t.Fatal("privileged guest role was accepted")
		}
	})
}

func TestGuestSessionPropagatesDomainFailures(t *testing.T) {
	fault := errors.New("guest session fault")

	t.Run("role listing", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listRolesErr = fault
		_, err := auth.GuestSession(t.Context(), "workspace-primary", "sales")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("guest user write", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "role-customer", Key: "customer", Status: identitymodel.IdentityStatusActive})
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer"}
		identityRepository.upsertUserErr = fault
		_, err := auth.GuestSession(t.Context(), "workspace-primary", "sales")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("role assignment", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "role-customer", Key: "customer", Status: identitymodel.IdentityStatusActive})
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer"}
		identityRepository.assignRoleErr = fault
		_, err := auth.GuestSession(t.Context(), "workspace-primary", "sales")
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("session issuance", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.roles = append(identityRepository.roles, identitymodel.IdentityRole{ID: "role-customer", Key: "customer", Status: identitymodel.IdentityStatusActive})
		identityRepository.roleDefinitions["customer"] = identitymodel.RoleSchema{Key: "customer", Name: "Customer"}
		identityRepository.listAssignmentsErr = fault
		_, err := auth.GuestSession(t.Context(), "workspace-primary", "sales")
		assertExternalAuthFault(t, err, fault)
	})
}
