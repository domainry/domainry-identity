package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
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
		Roles:   []identitymodel.RoleSchema{{Key: "admin", Name: "Admin", Permissions: []string{"identity.roles.list"}, RecordScope: "all_records", DataPermissions: []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records"}}}},
	}
}

func TestMetadataCandidateValidatesResourcesCreatedTogetherAsOneGraph(t *testing.T) {
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)}, Permissions: allowMetadataCandidatePermissions("identity.roles.list")})
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

func TestMetadataCandidateKeepsApplicationObjectReferencesOpaqueForRuntimeFinalValidation(t *testing.T) {
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: loadMetadataCandidateFixture(t)}, Permissions: allowMetadataCandidatePermissions("identity.roles.list")})
	role := json.RawMessage(`{"key":"coach","name":"Coach","record_scope":"all_records","data_permissions":[{"object_key":"booking","scope":"all_records"}],"field_permissions":[{"object_key":"booking","field_key":"member_id","readable":true}]}`)
	mutation := metadatamodel.MetadataDefinitionMutation{Operation: "create", ResourceType: "role", ResourceKey: "coach", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: role}}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{mutation}); err != nil {
		t.Fatalf("role referencing published application schema rejected: %#v", err)
	}

}

func TestMetadataCandidateRequiresRoleCleanupWhenLastDedicatedActionPermissionIsRetired(t *testing.T) {
	manifest := loadMetadataCandidateFixture(t)
	action := definitionmodel.ActionSchema{Key: "customer.approve", ObjectKey: "customer", Label: "Approve", Kind: "record_operation", AuditEvent: "customer.approved"}
	manifest.Actions = []definitionmodel.ActionSchema{action}
	manifest.Roles = append(manifest.Roles, identitymodel.RoleSchema{Key: "reviewer", Name: "Reviewer", Permissions: []string{"customer.approve"}, RecordScope: "all_records", DataPermissions: []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records"}}})
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: manifest}, Permissions: allowMetadataCandidatePermissions("identity.roles.list", "customer.read")})
	retire := metadatamodel.MetadataDefinitionMutation{Operation: "archive", ResourceType: "action", ResourceKey: action.Key}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{retire}); apperror.CodeOf(err) != "backend.metadata.candidate_invalid" || !strings.Contains(apperror.ParamsOf(err)["diagnostic"], "reviewer retains retired action permission customer.approve") {
		t.Fatalf("dangling role permission error=%#v", err)
	}
	rolePayload := json.RawMessage(`{"key":"reviewer","name":"Reviewer","permissions":["customer.read"],"record_scope":"all_records","data_permissions":[{"object_key":"customer","scope":"all_records"}]}`)
	cleanup := metadatamodel.MetadataDefinitionMutation{Operation: "update", ResourceType: "role", ResourceKey: "reviewer", Request: metadatamodel.MetadataDefinitionUpsertRequest{Payload: rolePayload}}
	if err := service.ValidateMetadataCandidate(t.Context(), []metadatamodel.MetadataDefinitionMutation{retire, cleanup}); err != nil {
		t.Fatalf("same-draft action retirement and role cleanup rejected: %#v", err)
	}
}

func TestMetadataCandidateValidatesExternalPermissionKeysAsOneCurrentStateBatch(t *testing.T) {
	manifest := loadMetadataCandidateFixture(t)
	manifest.Actions = []definitionmodel.ActionSchema{{Key: "customer.approve", ObjectKey: "customer", Label: "Approve", Kind: "record_operation", AuditEvent: "customer.approved"}}
	manifest.Roles[0].Permissions = []string{"identity.roles.list", "customer.read", "customer.approve", "customer.read"}
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
	manifest.Roles[0].Permissions = []string{"missing.action"}
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataCandidateRepository{manifest: manifest}, Permissions: allowMetadataCandidatePermissions()})
	err := service.ValidateMetadataCandidate(t.Context(), nil)
	if apperror.CodeOf(err) != "backend.metadata.candidate_invalid" || !strings.Contains(apperror.ParamsOf(err)["diagnostic"], "backend.identity.permission_not_found") {
		t.Fatalf("unknown permission error=%#v", err)
	}
}
