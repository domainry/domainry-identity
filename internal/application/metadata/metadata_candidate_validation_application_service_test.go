package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
)

type metadataCandidateRepository struct {
	metadatarepository.MetadataRepository
	manifest       manifestmodel.ManifestSchema
	err            error
	definitions    map[string][]metadatamodel.MetadataDefinition
	definitionErrs map[string]error
	versions       map[string][]metadatamodel.MetadataDefinitionVersion
	versionErrs    map[string]error
}

type metadataCandidatePermissionValidator struct {
	allowed map[string]bool
	calls   [][]string
}

func (validator *metadataCandidatePermissionValidator) ValidatePermissionSelections(keys []string) error {
	validator.calls = append(validator.calls, append([]string(nil), keys...))
	for _, key := range keys {
		if !validator.allowed[key] {
			return &apperror.AppError{Kind: apperror.KindBadRequest, Code: "backend.identity.permission_not_found", Params: map[string]string{"permission": key}}
		}
	}
	return nil
}

func allowMetadataCandidatePermissions(keys ...string) *metadataCandidatePermissionValidator {
	validator := &metadataCandidatePermissionValidator{allowed: map[string]bool{}}
	for _, key := range keys {
		validator.allowed[key] = true
	}
	return validator
}

func (r metadataCandidateRepository) LoadManifest(context.Context, identitymodel.SystemScope) (manifestmodel.ManifestSchema, error) {
	return r.manifest, r.err
}

func (r metadataCandidateRepository) ListDefinitions(_ context.Context, _ identitymodel.SystemScope, resourceType string) ([]metadatamodel.MetadataDefinition, error) {
	return r.definitions[resourceType], r.definitionErrs[resourceType]
}

func (r metadataCandidateRepository) ListDefinitionVersions(_ context.Context, _ identitymodel.SystemScope, resourceType, resourceKey string) ([]metadatamodel.MetadataDefinitionVersion, error) {
	key := fmt.Sprintf("%s/%s", resourceType, resourceKey)
	return r.versions[key], r.versionErrs[key]
}

func loadMetadataCandidateFixture(t *testing.T) manifestmodel.ManifestSchema {
	t.Helper()
	return manifestmodel.ManifestSchema{
		Objects: []definitionmodel.ObjectSchema{{Key: "customer", Name: "Customer", Description: "Customer", Fields: []definitionmodel.FieldSchema{{Key: "name", Name: "Name", Type: "text"}}}},
		Roles:   []identitymodel.RoleSchema{{Key: "admin", Name: "Admin", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "identity.roles.list")}},
	}
}

func TestMetadataCandidateValidatesResourcesCreatedTogetherAsOneGraph(t *testing.T) {
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)}, Permissions: allowMetadataCandidatePermissions("identity.roles.list", "booking.read")})
	mutations := []metadatamodel.MetadataDefinitionMutation{
		{Operation: "create", ResourceType: "object", ResourceKey: "project", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: json.RawMessage(`{"key":"project","name":"Project","description":"Project"}`)}},
		{Operation: "create", ResourceType: "field", ResourceKey: "project.name", Request: metadatamodel.MetadataDefinitionUpsertRequest{ObjectKey: "project", Payload: json.RawMessage(`{"key":"name","name":"Name","type":"text","required":true}`)}},
		{Operation: "create", ResourceType: "action", ResourceKey: "project.activate", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: json.RawMessage(`{"key":"project.activate","object_key":"project","label":"Activate","kind":"record_operation","audit_event":"project.activated"}`)}},
	}
	if err := service.ValidateMetadataCandidate(t.Context(), mutations); err != nil {
		t.Fatalf("composed candidate rejected: %#v", err)
	}
}

func TestMetadataCandidateRejectsDanglingReferencesBeforePersistence(t *testing.T) {
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)}, Permissions: allowMetadataCandidatePermissions("identity.roles.list")})
	mutations := []metadatamodel.MetadataDefinitionMutation{{Operation: "create", ResourceType: "field", ResourceKey: "missing.name", Request: metadatamodel.MetadataDefinitionUpsertRequest{ObjectKey: "missing", Payload: json.RawMessage(`{"key":"name","name":"Name","type":"text"}`)}}}
	err := service.ValidateMetadataCandidate(t.Context(), mutations)
	if apperror.CodeOf(err) != "backend.metadata.candidate_invalid" {
		t.Fatalf("error=%v", err)
	}
}

func TestIdentityProfileBindingValidationDefaultsBackendProtocolFields(t *testing.T) {
	runtime := &metadataLifecycleRuntimeStub{
		snapshot: metadatamodel.MetadataSchemaSnapshot{
			Objects: []definitionmodel.ObjectSchema{
				{
					Key: "staff_profile",
					Fields: []definitionmodel.FieldSchema{
						{Key: "identity_user", Type: "relation", Unique: true, Config: map[string]any{"object_key": "identity_user"}},
					},
				},
			},
		},
	}
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Runtime: runtime})
	payload := json.RawMessage(`{"object_key":"staff_profile","identity_relation_field":"identity_user","business_identity":{"key":"staff"},"default_visibility":"when_readable"}`)
	normalized, err := service.ValidateMetadataDefinitionPayload(t.Context(), "identity_profile_binding", metadatamodel.MetadataDefinitionUpsertRequest{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	var binding identitymodel.IdentityProfileExtension
	if err := json.Unmarshal(normalized.Payload, &binding); err != nil {
		t.Fatal(err)
	}
	if binding.Cardinality != "one_to_one" {
		t.Fatalf("backend defaults were not materialized: %#v", binding)
	}
}

func TestMetadataCandidateKeepsApplicationObjectReferencesOpaqueForRuntimeFinalValidation(t *testing.T) {
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)}, Permissions: allowMetadataCandidatePermissions("identity.roles.list", "booking.read")})
	role := json.RawMessage(`{"key":"coach","name":"Coach","permissions":[{"permission_key":"booking.read","data_scope":"all"}],"field_permissions":[{"object_key":"booking","field_key":"member_id","read":true}]}`)
	mutation := metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: "coach", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: role}}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{mutation}); err != nil {
		t.Fatalf("role referencing published application schema rejected: %#v", err)
	}

}

func TestMetadataCandidateValidatesProjectFieldOverlayAgainstPublishedProjectObjects(t *testing.T) {
	runtime := &metadataProjectObjectRuntimeStub{
		metadataLifecycleRuntimeStub: metadataLifecycleRuntimeStub{},
		objects: []definitionmodel.ObjectSchema{{
			Key: "booking", Name: "Booking", Fields: []definitionmodel.FieldSchema{{Key: "owner", Name: "Owner", Type: "user"}, {Key: "email", Name: "Email", Type: "email"}},
			// Runtime owns and has already validated this object metadata. It is
			// deliberately not imported into Identity's authored graph.
			Validations: []definitionmodel.ValidationSchema{{Key: "runtime-only", ObjectKey: "another_object"}},
		}},
	}
	service := NewMetadataApplicationService(MetadataApplicationDependencies{
		Repository:  metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)},
		Permissions: allowMetadataCandidatePermissions("identity.roles.list", "booking.read"),
		Runtime:     runtime,
	})
	role := json.RawMessage(`{"key":"analyst","name":"Analyst","field_permissions":[{"object_key":"booking","field_key":"email","read":true}],"project_field_permission_override":true}`)
	mutation := metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: "analyst", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: role}}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{mutation}); err != nil {
		t.Fatalf("project role overlay rejected: %#v", err)
	}
}

type metadataProjectObjectRuntimeStub struct {
	metadataLifecycleRuntimeStub
	objects []definitionmodel.ObjectSchema
}

func (runtime *metadataProjectObjectRuntimeStub) ProjectObjects() []definitionmodel.ObjectSchema {
	return append([]definitionmodel.ObjectSchema(nil), runtime.objects...)
}

func TestMetadataCandidateRequiresRoleCleanupWhenLastDedicatedActionPermissionIsRetired(t *testing.T) {
	manifest := loadMetadataCandidateFixture(t)
	action := definitionmodel.ActionSchema{Key: "customer.approve", ObjectKey: "customer", Label: "Approve", Kind: "record_operation", AuditEvent: "customer.approved"}
	manifest.Actions = []definitionmodel.ActionSchema{action}
	manifest.Roles = append(manifest.Roles, identitymodel.RoleSchema{Key: "reviewer", Name: "Reviewer", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "customer.approve")})
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: manifest}, Permissions: allowMetadataCandidatePermissions("identity.roles.list", "customer.read")})
	retire := metadatamodel.MetadataDefinitionMutation{Operation: "archive", ResourceType: "action", ResourceKey: action.Key}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{retire}); apperror.CodeOf(err) != "backend.metadata.candidate_invalid" || !strings.Contains(apperror.ParamsOf(err)["diagnostic"], "reviewer retains retired action permission customer.approve") {
		t.Fatalf("dangling role permission error=%#v", err)
	}
	rolePayload := json.RawMessage(`{"key":"reviewer","name":"Reviewer","permissions":[{"permission_key":"customer.read","data_scope":"all"}]}`)
	cleanup := metadatamodel.MetadataDefinitionMutation{Operation: "update", ResourceType: "role", ResourceKey: "reviewer", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: rolePayload}}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{retire, cleanup}); err != nil {
		t.Fatalf("same-draft action retirement and role cleanup rejected: %#v", err)
	}
}

func TestMetadataCandidateValidatesExternalPermissionKeysAsOneCurrentStateBatch(t *testing.T) {
	manifest := loadMetadataCandidateFixture(t)
	manifest.Actions = []definitionmodel.ActionSchema{{Key: "customer.approve", ObjectKey: "customer", Label: "Approve", Kind: "record_operation", AuditEvent: "customer.approved"}}
	manifest.Roles[0].Permissions = []identitymodel.RolePermission{{PermissionKey: "identity.roles.list", DataScope: identitymodel.IdentityDataScopeAll}, {PermissionKey: "customer.read", DataScope: identitymodel.IdentityDataScopeAll}, {PermissionKey: "customer.approve", DataScope: identitymodel.IdentityDataScopeAll}, {PermissionKey: "customer.read", DataScope: identitymodel.IdentityDataScopeAll}}
	permissions := allowMetadataCandidatePermissions("identity.roles.list", "customer.read")
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: manifest}, Permissions: permissions})

	if err := service.ValidateMetadataCandidate(t.Context(), nil); err != nil {
		t.Fatalf("candidate permission validation failed: %v", err)
	}
	if len(permissions.calls) != 1 || strings.Join(permissions.calls[0], ",") != "customer.read,identity.roles.list" {
		t.Fatalf("permission validation calls=%v", permissions.calls)
	}
}

func TestMetadataCandidateFailsClosedWhenCurrentPermissionValidatorIsUnavailable(t *testing.T) {
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)}})
	err := service.ValidateMetadataCandidate(t.Context(), nil)
	if apperror.CodeOf(err) != "backend.metadata.candidate_invalid" || !strings.Contains(apperror.ParamsOf(err)["diagnostic"], "validator is unavailable") {
		t.Fatalf("missing permission validator error=%#v", err)
	}
}

func TestMetadataCandidateRejectsUnknownCurrentPermissionKey(t *testing.T) {
	manifest := loadMetadataCandidateFixture(t)
	manifest.Roles[0].Permissions = identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "missing.action")
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: manifest}, Permissions: allowMetadataCandidatePermissions()})
	err := service.ValidateMetadataCandidate(t.Context(), nil)
	if apperror.CodeOf(err) != "backend.metadata.candidate_invalid" || !strings.Contains(apperror.ParamsOf(err)["diagnostic"], "backend.identity.permission_not_found") {
		t.Fatalf("unknown permission error=%#v", err)
	}
}

type metadataProjectGrantRuntimeStub struct {
	metadataProjectObjectRuntimeStub
	role identitymodel.RoleSchema
}

func (runtime *metadataProjectGrantRuntimeStub) ProjectRoleDefinition(key string) (identitymodel.RoleSchema, bool) {
	return runtime.role, key == runtime.role.Key
}

func TestMetadataProjectGrantTrustIsExactAndDoesNotSkipCurrentPermissionValidation(t *testing.T) {
	// The host owns this system field; Identity's partial object graph does not.
	trusted := identitymodel.RolePermission{PermissionKey: "customer.read", DataPolicy: &identitysdk.ProjectDataPolicy{Operator: "eq", FieldKey: "owner_user_id", SubjectClaim: "id"}}
	project := identitymodel.RoleSchema{Key: "sales", Name: "Sales", Permissions: []identitymodel.RolePermission{trusted}}
	for _, test := range []struct {
		name      string
		mutate    func(*identitymodel.RoleSchema)
		allowRead bool
		want      string
	}{
		{name: "unchanged source grant", allowRead: true},
		{name: "modified source grant", allowRead: true, mutate: func(role *identitymodel.RoleSchema) { role.Permissions[0].DataPolicy.FieldKey = "untrusted_field" }, want: "unknown or disabled field"},
		{name: "new invalid grant", allowRead: true, mutate: func(role *identitymodel.RoleSchema) {
			role.Permissions = append(role.Permissions, identitymodel.RolePermission{PermissionKey: "customer.update", DataScope: "invalid"})
		}, want: "unsupported scope"},
		{name: "unmarked metadata cannot claim source trust", allowRead: true, mutate: func(role *identitymodel.RoleSchema) { role.ProjectPermissionOverride = false }, want: "unknown or disabled field"},
		{name: "source key no longer selectable", allowRead: false, want: "backend.identity.permission_not_found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(project)
			if err != nil {
				t.Fatal(err)
			}
			var overlay identitymodel.RoleSchema
			if err := json.Unmarshal(payload, &overlay); err != nil {
				t.Fatal(err)
			}
			overlay.ProjectPermissionOverride = true
			if test.mutate != nil {
				test.mutate(&overlay)
			}
			manifest := loadMetadataCandidateFixture(t)
			manifest.Roles = append(manifest.Roles, overlay)
			permissions := allowMetadataCandidatePermissions("identity.roles.list", "customer.update")
			permissions.allowed["customer.read"] = test.allowRead
			service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: manifest}, Permissions: permissions, Runtime: &metadataProjectGrantRuntimeStub{role: project}})
			err = service.ValidateMetadataCandidate(t.Context(), nil)
			if test.want == "" {
				if err != nil {
					t.Fatalf("unchanged host grant rejected: %v", err)
				}
				if len(permissions.calls) != 1 || !strings.Contains(strings.Join(permissions.calls[0], ","), "customer.read") {
					t.Fatalf("trusted grant bypassed registry validation: %v", permissions.calls)
				}
			} else if apperror.CodeOf(err) != "backend.metadata.candidate_invalid" || !strings.Contains(apperror.ParamsOf(err)["diagnostic"], test.want) {
				t.Fatalf("error=%v params=%v want=%q", err, apperror.ParamsOf(err), test.want)
			}
		})
	}
}
