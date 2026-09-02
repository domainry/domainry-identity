package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type roleDefinitionPublisherSpy struct {
	permissionDefinitionLoads int
	publishedRoleKey          string
	publishedPermissionKeys   []string
	createdRole               identitymodel.RoleSchema
}

func (s *roleDefinitionPublisherSpy) IdentityRolePermissionDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	s.permissionDefinitionLoads++
	return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, errors.New("permission configuration load must not run during publish")
}

func (*roleDefinitionPublisherSpy) IdentityRoleDataScopeDefinition(context.Context, string, identitymodel.Principal) (identitymodel.RoleSchema, identitymodel.IdentityRoleDefinitionRevision, bool, error) {
	return identitymodel.RoleSchema{}, identitymodel.IdentityRoleDefinitionRevision{}, false, nil
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

func (s *roleDefinitionPublisherSpy) PublishIdentityRolePermissions(_ context.Context, roleKey string, keys []string, _, _, _ string, _ identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	s.publishedRoleKey = roleKey
	s.publishedPermissionKeys = append([]string(nil), keys...)
	return identitymodel.IdentityRoleDefinitionRevision{SchemaVersion: "2", SchemaHash: "published-hash"}, nil
}

func (*roleDefinitionPublisherSpy) PublishIdentityRoleDataScopes(context.Context, string, []identitymodel.DataPermission, string, string, string, identitymodel.Principal) (identitymodel.IdentityRoleDefinitionRevision, error) {
	return identitymodel.IdentityRoleDefinitionRevision{}, nil
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
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", Role: identitymodel.RoleSchema{Permissions: []string{identitycontract.IdentityActionRolePermissionsPublish}}}
	ctx := requestcontext.WithWorkspaceID(context.Background(), "workspace-primary")

	configuration, err := service.PublishPermissions(ctx, "reviewer", identitymodel.IdentityRolePermissionPublicationRequest{
		PermissionKeys: []string{identitycontract.IdentityActionRolesList}, ExpectedSchemaHash: "before-hash",
		BusinessReason: "grant role list", OperationID: "publish-1",
	}, principal)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.permissionDefinitionLoads != 0 {
		t.Fatalf("publish acquired the list action through %d configuration loads", publisher.permissionDefinitionLoads)
	}
	if publisher.publishedRoleKey != "reviewer" || len(publisher.publishedPermissionKeys) != 1 || publisher.publishedPermissionKeys[0] != identitycontract.IdentityActionRolesList {
		t.Fatalf("published role mutation = %q %#v", publisher.publishedRoleKey, publisher.publishedPermissionKeys)
	}
	if configuration.SchemaVersion != "2" || configuration.SchemaHash != "published-hash" {
		t.Fatalf("published configuration = %#v", configuration)
	}
}

func TestRoleCreateIsFailClosedForDataAuthority(t *testing.T) {
	publisher := &roleDefinitionPublisherSpy{}
	service := NewIdentityRoleDefinitionPublicationService(nil, roleDefinitionPublicationCatalog(t), publisher)
	principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", Role: identitymodel.RoleSchema{Permissions: []string{identitycontract.IdentityActionRolesCreate}}}

	configuration, err := service.Create(t.Context(), identitymodel.IdentityRoleDefinitionMutationRequest{
		Role: identitymodel.RoleSchema{
			Key: " Reviewer ", Name: " Reviewer ", Permissions: []string{identitycontract.IdentityActionRolesList},
			RecordScope: "all_records", DataPermissions: []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records"}},
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
	if created.Key != "reviewer" || created.RecordScope != "none" || len(created.DataPermissions) != 0 || len(created.FieldPermissions) != 0 || len(created.ReferencePermissions) != 0 || len(created.ExportRules) != 0 || len(created.GrantableRoleKeys) != 0 || len(created.GuardrailKeys) != 0 || created.ProvisionToWorkspaces {
		t.Fatalf("new role did not fail closed: %#v", created)
	}
	if created.Audience != identitymodel.IdentityRoleAudienceAny || created.AssignmentMode != identitymodel.IdentityRoleAssignmentManual || created.RiskLevel != identitymodel.IdentityRoleRiskNormal {
		t.Fatalf("new role defaults = %#v", created)
	}
	if configuration.SchemaVersion != "1" || configuration.SchemaHash != "created-hash" {
		t.Fatalf("created configuration = %#v", configuration)
	}
}
