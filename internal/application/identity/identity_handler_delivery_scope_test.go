package identity

import (
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestHandlerDeliveryResolvesOnlyPublishedActiveBindingForExactUser(t *testing.T) {
	repository := &profileBindingRepositoryStub{found: true, binding: identitymodel.IdentityProfileBinding{
		WorkspaceID: "workspace", BindingKey: "employee", ObjectKey: "employee_profile", ProfileID: "profile-1",
		IdentityUserID: "user-1", Status: identitymodel.IdentityProfileBindingActive, Version: 7,
	}}
	profiles := NewIdentityProfileBindingApplicationService(IdentityProfileBindingDependencies{
		Repository: repository,
		Objects: func() []definitionmodel.ObjectSchema {
			return []definitionmodel.ObjectSchema{{Key: "employee_profile"}}
		},
		Extensions: func() []identitymodel.IdentityProfileExtension {
			return []identitymodel.IdentityProfileExtension{{ObjectKey: "employee_profile", BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "employee"}}}
		},
	})
	service := &IdentityHandlerDeliveryApplicationService{dependencies: IdentityHandlerDeliveryDependencies{ProfileBindings: profiles}}
	selector := &IdentityHandlerProfileBindingSelector{BindingKey: "employee", ObjectKey: "employee_profile", ProfileID: "profile-1"}
	binding, err := service.resolveRequestedProfileBinding(t.Context(), "workspace", "user-1", selector)
	if err != nil || binding == nil || binding.Version != 7 {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}

	for name, mutate := range map[string]func(){
		"unpublished binding": func() { selector.BindingKey = "other" },
		"different user":      func() { repository.binding.IdentityUserID = "user-2" },
		"inactive":            func() { repository.binding.Status = identitymodel.IdentityProfileBindingSuspended },
		"invalid version":     func() { repository.binding.Version = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			originalSelector, originalBinding := *selector, repository.binding
			mutate()
			defer func() { *selector, repository.binding = originalSelector, originalBinding }()
			if resolved, resolveErr := service.resolveRequestedProfileBinding(t.Context(), "workspace", "user-1", selector); resolved != nil || apperror.CodeOf(resolveErr) != "backend.identity.handler_projection_denied" {
				t.Fatalf("resolved=%+v err=%v", resolved, resolveErr)
			}
		})
	}

	repository.err = errors.New("binding read failed")
	if _, err := service.resolveRequestedProfileBinding(t.Context(), "workspace", "user-1", selector); !errors.Is(err, repository.err) {
		t.Fatalf("repository error=%v", err)
	}
}

func TestHandlerDeliveryPurposePermissionPreservesCanonicalOrganizationScopes(t *testing.T) {
	permission := identitycontract.IdentityHandlerDeliveryUpdatePermission
	principal := func(scope identitymodel.IdentityDataScope) identitymodel.Principal {
		return identitymodel.Principal{
			Known: true, UserID: "actor", OrgID: "hq", OrgScopeIDs: []string{"hq", "store-a"},
			SupportOrgScopeIDs: []string{"customer-a", "customer-a-child"},
			Role:               identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(scope, permission)},
		}
	}
	tests := []struct {
		name      string
		principal identitymodel.Principal
		current   identitymodel.IdentityUser
		desired   identitymodel.IdentityUser
		want      bool
	}{
		{name: "all", principal: principal(identitymodel.IdentityDataScopeAll), current: identitymodel.IdentityUser{ID: "user", OrgID: "other"}, desired: identitymodel.IdentityUser{ID: "user", OrgID: "elsewhere"}, want: true},
		{name: "org", principal: principal(identitymodel.IdentityDataScopeOrg), current: identitymodel.IdentityUser{ID: "user", OrgID: "hq"}, desired: identitymodel.IdentityUser{ID: "user", OrgID: "hq"}, want: true},
		{name: "org move denied", principal: principal(identitymodel.IdentityDataScopeOrg), current: identitymodel.IdentityUser{ID: "user", OrgID: "hq"}, desired: identitymodel.IdentityUser{ID: "user", OrgID: "store-a"}},
		{name: "org child", principal: principal(identitymodel.IdentityDataScopeOrgChild), current: identitymodel.IdentityUser{ID: "user", OrgID: "store-a"}, desired: identitymodel.IdentityUser{ID: "user", OrgID: "store-a"}, want: true},
		{name: "target org", principal: principal(identitymodel.IdentityDataScopeTargetOrg), current: identitymodel.IdentityUser{ID: "user", OrgID: "customer-a-child"}, desired: identitymodel.IdentityUser{ID: "user", OrgID: "customer-a-child"}, want: true},
		{name: "target org denied", principal: principal(identitymodel.IdentityDataScopeTargetOrg), current: identitymodel.IdentityUser{ID: "user", OrgID: "other"}, desired: identitymodel.IdentityUser{ID: "user", OrgID: "other"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := handlerDeliveryScopeAllows(test.principal, permission, test.current, test.desired, true); got != test.want {
				t.Fatalf("scope allow=%v want=%v", got, test.want)
			}
		})
	}
}

func TestHandlerDeliveryPurposePermissionDoesNotAliasGenericCRUD(t *testing.T) {
	principal := identitymodel.Principal{
		Known: true, UserID: "actor",
		Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, identitycontract.IdentityHandlerDeliveryCreatePermission)},
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, identitycontract.IdentityHandlerDeliveryCreatePermission) {
		t.Fatal("purpose-specific grant missing")
	}
	for _, generic := range []string{
		identitycontract.IdentityUsersCreatePermission,
		identitycontract.IdentityUserRoleAssignmentsAccountUpdatePermission,
		identitycontract.IdentityActionProfileBindingsCommand,
	} {
		if identitycontract.IdentityRoleHasPermissionKey(principal.Role, generic) {
			t.Fatalf("purpose-specific grant aliased generic permission %q", generic)
		}
	}
}
