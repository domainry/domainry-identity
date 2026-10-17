package identity

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type roleDefinitionPublisherSpy struct {
	permissionDefinitionLoads int
	currentRole               identitymodel.RoleSchema
	publishedRoleKey          string
	publishedPermissions      []identitymodel.RolePermission
	createdRole               identitymodel.RoleSchema
}

func (s *roleDefinitionPublisherSpy) IdentityRolePermissionDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	s.permissionDefinitionLoads++
	return s.currentRole, identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: "1", SchemaHash: "before-hash"}, true, nil
}

func (s *roleDefinitionPublisherSpy) IdentityRolePermissionDefinitionForPublication(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	s.permissionDefinitionLoads++
	return s.currentRole, identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: "1", SchemaHash: "before-hash"}, true, nil
}

func (*roleDefinitionPublisherSpy) IdentityRoleFieldPermissionDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, nil
}

func (s *roleDefinitionPublisherSpy) CreateIdentityRoleDefinition(_ context.Context, role identitymodel.RoleSchema, _, _ string, _ identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	s.createdRole = role
	return identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: "1", SchemaHash: "created-hash"}, nil
}

func (*roleDefinitionPublisherSpy) UpdateIdentityRoleDefinition(context.Context, string, identitymodel.IdentityRoleDefinitionUpdateRequest, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, error) {
	return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, nil
}

func (*roleDefinitionPublisherSpy) DisableIdentityRoleDefinition(context.Context, string, string, string, string, identitymodel.Principal) error {
	return nil
}

func (s *roleDefinitionPublisherSpy) PublishIdentityRolePermissions(_ context.Context, roleKey string, permissions []identitymodel.RolePermission, _, _, _ string, _ identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	s.publishedRoleKey = roleKey
	s.publishedPermissions = append([]identitymodel.RolePermission(nil), permissions...)
	return identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: "2", SchemaHash: "published-hash"}, nil
}

func (*roleDefinitionPublisherSpy) PublishIdentityRoleFieldPermissions(context.Context, string, []identitymodel.FieldPermission, string, string, string, identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	return identitymodel.IdentityRoleDefinitionRevision{}, nil
}

func roleDefinitionPublicationCatalog(t *testing.T) *IdentityPermissionCatalogApplicationService {
	t.Helper()
	registry, err := NewStandaloneIdentityAuthorizationSliceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewIdentityPermissionCatalogApplicationService(&permissionCatalogRepositoryStub{}, registry, "workspace-primary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.ReconcileOwner(t.Context(), IdentityBuiltinAuthorizationOwner); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestRolePermissionPublishRequiresOnlyItsExactAction(t *testing.T) {
	repository := &identityScopedRepository{roles: []identitymodel.IdentityRole{{ID: "reviewer", Key: "reviewer", Label: "Reviewer", Status: identitymodel.IdentityStatusActive}}}
	publisher := &roleDefinitionPublisherSpy{}
	service := NewIdentityRoleDefinitionPublicationService(NewIdentityApplicationService(repository, nil), roleDefinitionPublicationCatalog(t), publisher)
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityActionRolePermissionsPublish)}}
	ctx := requestcontext.WithWorkspaceID(context.Background(), "workspace-primary")

	configuration, err := service.PublishPermissions(ctx, "reviewer", identitymodel.IdentityRolePermissionPublicationRequest{
		Permissions: identityTestRolePermissions(identitycontract.IdentityActionRolesList), ExpectedSchemaHash: "before-hash",
		BusinessReason: "grant role list", OperationID: "publish-1",
	}, principal)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.permissionDefinitionLoads != 1 {
		t.Fatalf("publish current-definition loads = %d", publisher.permissionDefinitionLoads)
	}
	if publisher.publishedRoleKey != "reviewer" || len(publisher.publishedPermissions) != 1 || publisher.publishedPermissions[0].PermissionKey != identitycontract.IdentityActionRolesList || publisher.publishedPermissions[0].DataScope != identitymodel.IdentityDataScopeAll {
		t.Fatalf("published role mutation = %q %#v", publisher.publishedRoleKey, publisher.publishedPermissions)
	}
	if configuration.SchemaVersion != "2" || configuration.SchemaHash != "published-hash" {
		t.Fatalf("published configuration = %#v", configuration)
	}
}

func TestRolePermissionPublishPreservesExistingBundledPermission(t *testing.T) {
	repository := &identityScopedRepository{roles: []identitymodel.IdentityRole{{ID: "reviewer", Key: "reviewer", Label: "Reviewer", Status: identitymodel.IdentityStatusActive}}}
	bundled := identitycontract.IdentityOrganizationUnitDeliveryResolvePermission
	publisher := &roleDefinitionPublisherSpy{currentRole: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(bundled)}}
	service := NewIdentityRoleDefinitionPublicationService(NewIdentityApplicationService(repository, nil), roleDefinitionPublicationCatalog(t), publisher)
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityActionRolePermissionsPublish)}}
	ctx := requestcontext.WithWorkspaceID(context.Background(), "workspace-primary")

	requested := identityTestRolePermissions(bundled, identitycontract.IdentityActionRolesList)
	if _, err := service.PublishPermissions(ctx, "reviewer", identitymodel.IdentityRolePermissionPublicationRequest{
		Permissions: requested, ExpectedSchemaHash: "before-hash", BusinessReason: "add role list", OperationID: "publish-preserve-bundle",
	}, principal); err != nil {
		t.Fatal(err)
	}
	if len(publisher.publishedPermissions) != 2 || publisher.publishedPermissions[0].PermissionKey != bundled || publisher.publishedPermissions[1].PermissionKey != identitycontract.IdentityActionRolesList {
		t.Fatalf("published permissions=%#v", publisher.publishedPermissions)
	}
}

func TestRolePermissionPublishCannotRewriteExistingBundledPermissionScope(t *testing.T) {
	repository := &identityScopedRepository{roles: []identitymodel.IdentityRole{{ID: "reviewer", Key: "reviewer", Label: "Reviewer", Status: identitymodel.IdentityStatusActive}}}
	bundled := identitycontract.IdentityOrganizationUnitDeliveryResolvePermission
	publisher := &roleDefinitionPublisherSpy{currentRole: identitymodel.RoleSchema{Permissions: identityTestScopedRolePermissions(identitymodel.IdentityDataScopeOwner, bundled)}}
	service := NewIdentityRoleDefinitionPublicationService(NewIdentityApplicationService(repository, nil), roleDefinitionPublicationCatalog(t), publisher)
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityActionRolePermissionsPublish)}}
	ctx := requestcontext.WithWorkspaceID(context.Background(), "workspace-primary")

	_, err := service.PublishPermissions(ctx, "reviewer", identitymodel.IdentityRolePermissionPublicationRequest{
		Permissions: identityTestScopedRolePermissions(identitymodel.IdentityDataScopeAll, bundled), ExpectedSchemaHash: "before-hash",
		BusinessReason: "widen bundled grant", OperationID: "publish-rewrite-bundle",
	}, principal)
	if apperror.CodeOf(err) != "backend.identity.permission_not_directly_grantable" {
		t.Fatalf("bundled scope rewrite error=%v", err)
	}
	if len(publisher.publishedPermissions) != 0 {
		t.Fatalf("bundled scope rewrite was published: %#v", publisher.publishedPermissions)
	}
}

func TestRoleCreateIsFailClosedForDataAuthority(t *testing.T) {
	publisher := &roleDefinitionPublisherSpy{}
	service := NewIdentityRoleDefinitionPublicationService(nil, roleDefinitionPublicationCatalog(t), publisher)
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", Role: identitymodel.RoleSchema{Permissions: identityTestRolePermissions(identitycontract.IdentityActionRolesCreate)}}

	configuration, err := service.Create(t.Context(), identitymodel.IdentityRoleDefinitionMutationRequest{
		Role: identitymodel.RoleSchema{
			Key: " Reviewer ", Name: " Reviewer ", Permissions: []identitymodel.RolePermission{
				{PermissionKey: identitycontract.IdentityActionRolesList, DataScope: identitymodel.IdentityDataScopeAll},
			},
			FieldPermissions:     []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "secret", Read: true}},
			ReferencePermissions: []identitymodel.ReferencePermission{{SourceObjectKey: "customer", RelationFieldKey: "owner", TargetObjectKey: "identity_user"}},
			ExportRules:          []identitymodel.ExportRule{{ObjectKey: "customer", Mode: "allow_list", Fields: []string{"id"}}},
			GrantableRoleKeys:    []string{"*"}, GuardrailKeys: []string{"guardrail"}, ProvisionToWorkspaces: true,
		},
		BusinessReason: "create reviewer", OperationID: "create-1",
	}, principal)
	if err != nil {
		t.Fatal(err)
	}
	created := publisher.createdRole
	if created.Key != "reviewer" || len(created.Permissions) != 1 || created.Permissions[0].PermissionKey != identitycontract.IdentityActionRolesList || created.Permissions[0].DataScope != identitymodel.IdentityDataScopeAll || len(created.FieldPermissions) != 0 || len(created.ReferencePermissions) != 0 || len(created.ExportRules) != 0 || len(created.GrantableRoleKeys) != 0 || len(created.GuardrailKeys) != 0 || created.ProvisionToWorkspaces {
		t.Fatalf("new role did not fail closed: %#v", created)
	}
	if created.Audience != identitymodel.IdentityRoleAudienceAny || created.AssignmentMode != identitymodel.IdentityRoleAssignmentManual || created.RiskLevel != identitymodel.IdentityRoleRiskNormal {
		t.Fatalf("new role defaults = %#v", created)
	}
	if configuration.SchemaVersion != "1" || configuration.SchemaHash != "created-hash" {
		t.Fatalf("created configuration = %#v", configuration)
	}
}
