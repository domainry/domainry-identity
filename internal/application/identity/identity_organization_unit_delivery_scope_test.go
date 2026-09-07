package identity

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type organizationUnitDeliveryAuthStub struct {
	claims    authmodel.AuthClaims
	principal identitymodel.Principal
}

func (stub organizationUnitDeliveryAuthStub) VerifyAccessToken(context.Context, string) (authmodel.AuthClaims, error) {
	return stub.claims, nil
}

func (stub organizationUnitDeliveryAuthStub) PrincipalFromBearer(context.Context, string, string) (identitymodel.Principal, error) {
	return stub.principal, nil
}

type organizationUnitDeliveryApplicationStub struct {
	workspaceID string
	registered  bool
}

func (stub organizationUnitDeliveryApplicationStub) Registered(context.Context, string) (bool, error) {
	return stub.registered, nil
}

func (stub organizationUnitDeliveryApplicationStub) WorkspaceID() string { return stub.workspaceID }

type organizationUnitDeliveryRepositoryStub struct{}

func (organizationUnitDeliveryRepositoryStub) LockIdentityOrganizationUnitDeliveryParent(context.Context, string, string) (identitymodel.IdentityOrganizationUnit, bool, error) {
	return identitymodel.IdentityOrganizationUnit{}, false, nil
}

func (organizationUnitDeliveryRepositoryStub) GetIdentityOrganizationUnitDeliveryReceipt(context.Context, string, string) (identitymodel.IdentityOrganizationUnitDeliveryReceipt, bool, error) {
	return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, false, nil
}

func (organizationUnitDeliveryRepositoryStub) GetIdentityOrganizationUnitDeliveryState(context.Context, string, string) (identitymodel.IdentityOrganizationUnitDeliveryState, bool, error) {
	return identitymodel.IdentityOrganizationUnitDeliveryState{}, false, nil
}

func (organizationUnitDeliveryRepositoryStub) ResolveIdentityDeliveredOrganizationUnit(context.Context, string, string, identitymodel.IdentityOrganizationUnitType, identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityDeliveredOrganizationUnit, bool, error) {
	return identitymodel.IdentityDeliveredOrganizationUnit{}, false, nil
}

func (organizationUnitDeliveryRepositoryStub) ExecuteIdentityOrganizationUnitDelivery(context.Context, identitymodel.IdentityOrganizationUnitDeliveryMutation) (identitymodel.IdentityOrganizationUnitDeliveryReceipt, error) {
	return identitymodel.IdentityOrganizationUnitDeliveryReceipt{}, nil
}

func TestOrganizationUnitDeliveryScopesOnlyPersistedParent(t *testing.T) {
	permission := identitycontract.IdentityOrganizationUnitDeliveryCreatePermission
	principal := func(scope identitymodel.IdentityDataScope) identitymodel.Principal {
		return identitymodel.Principal{
			Known: true, UserID: "operator", OrgID: "company-a", OrgScopeIDs: []string{"company-a", "department-a"},
			SupportOrgScopeIDs: []string{"company-b", "department-b"},
			Role:               identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(scope, permission)},
		}
	}
	for _, test := range []struct {
		name string
		role identitymodel.Principal
		id   string
		want bool
	}{
		{name: "all", role: principal(identitymodel.IdentityDataScopeAll), id: "any", want: true},
		{name: "org", role: principal(identitymodel.IdentityDataScopeOrg), id: "company-a", want: true},
		{name: "org denied", role: principal(identitymodel.IdentityDataScopeOrg), id: "department-a"},
		{name: "org child", role: principal(identitymodel.IdentityDataScopeOrgChild), id: "department-a", want: true},
		{name: "target org", role: principal(identitymodel.IdentityDataScopeTargetOrg), id: "department-b", want: true},
		{name: "target denied", role: principal(identitymodel.IdentityDataScopeTargetOrg), id: "company-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := organizationUnitParentScopeAllows(test.role, permission, test.id); got != test.want {
				t.Fatalf("scope=%v want=%v", got, test.want)
			}
		})
	}
}

func TestOrganizationUnitDeliveryPermissionDoesNotAliasManagementOrStoreDelivery(t *testing.T) {
	role := identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, identitycontract.IdentityOrganizationUnitDeliveryCreatePermission)}
	for _, other := range []string{
		"identity.organization_units.create", "identity.organization_units.update",
		identitycontract.IdentityStoreOrganizationDeliveryCreatePermission,
	} {
		if identitycontract.IdentityRoleHasPermissionKey(role, other) {
			t.Fatalf("organization-unit delivery grant aliased %q", other)
		}
	}
}

func TestOrganizationUnitDeliveryCreateValidationRejectsRootAndMutationFields(t *testing.T) {
	valid := IdentityOrganizationUnitDeliveryRequest{
		ContractVersion: IdentityOrganizationUnitDeliveryContractVersionV1, AccessToken: "token", IdempotencyKey: "delivery-1",
		OrganizationID: "department", Code: "DEPARTMENT", Name: "Department", NodeType: identitymodel.IdentityOrganizationUnitDepartment,
		ParentOrganizationID: "company", ExpectedVersion: 0,
	}
	if err := validateIdentityOrganizationUnitDeliveryRequest(valid); err != nil {
		t.Fatal(err)
	}
	invalidType := valid
	invalidType.NodeType = identitymodel.IdentityOrganizationUnitCompany
	if err := validateIdentityOrganizationUnitDeliveryRequest(invalidType); apperror.CodeOf(err) != "backend.identity.organization_unit_type_invalid" {
		t.Fatalf("root node error=%v", err)
	}
	invalidType.NodeType = identitymodel.IdentityOrganizationUnitStore
	if err := validateIdentityOrganizationUnitDeliveryRequest(invalidType); apperror.CodeOf(err) != "backend.identity.organization_unit_type_invalid" {
		t.Fatalf("store node error=%v", err)
	}
	stale := valid
	stale.ExpectedVersion = 1
	if err := validateIdentityOrganizationUnitDeliveryRequest(stale); apperror.CodeOf(err) != "backend.identity.organization_unit_delivery_invalid" {
		t.Fatalf("stale create error=%v", err)
	}
}

func TestOrganizationUnitDeliveryAuthorizationFailsClosed(t *testing.T) {
	claims := authmodel.AuthClaims{Audience: "runtime-app", Subject: "operator", WorkspaceID: "workspace-primary", AuthorizationRevision: "revision-1"}
	principal := identitymodel.Principal{Known: true, UserID: "operator", WorkspaceID: "workspace-primary", AuthorizationRevision: "revision-1"}
	for _, test := range []struct {
		name       string
		claims     authmodel.AuthClaims
		principal  identitymodel.Principal
		registered bool
		want       string
	}{
		{name: "application audience", claims: claims, principal: principal, want: "identity.organization_unit_delivery_application_scope_mismatch"},
		{name: "actor", claims: claims, principal: func() identitymodel.Principal { value := principal; value.UserID = "other"; return value }(), registered: true, want: "backend.identity.organization_unit_actor_invalid"},
		{name: "authorization revision", claims: claims, principal: func() identitymodel.Principal {
			value := principal
			value.AuthorizationRevision = "revision-2"
			return value
		}(), registered: true, want: "auth.authorization_stale"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := NewIdentityOrganizationUnitDeliveryApplicationService(IdentityOrganizationUnitDeliveryDependencies{
				WorkspaceID:    "workspace-primary",
				Authentication: organizationUnitDeliveryAuthStub{claims: test.claims, principal: test.principal},
				Applications:   organizationUnitDeliveryApplicationStub{workspaceID: "workspace-primary", registered: test.registered},
				Identity:       &IdentityApplicationService{}, Repository: organizationUnitDeliveryRepositoryStub{},
			})
			if _, _, _, err := service.authorize(t.Context(), "token"); apperror.CodeOf(err) != test.want {
				t.Fatalf("authorization error=%v want=%s", err, test.want)
			}
		})
	}
}
