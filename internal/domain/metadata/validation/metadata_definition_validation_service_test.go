package validation

import (
	"context"
	"encoding/json"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func TestValidateDefinitionRequestOwnsEnvelopeAndNormalization(t *testing.T) {
	admin := identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, metadatacontract.MetadataActionDefinitionValidate)}}
	result, err := MetadataValidateDefinitionRequest(t.Context(), " action ", " create_order ", json.RawMessage(`{"key":"create_order"}`), admin,
		func(_ context.Context, resourceType, resourceKey string, payload json.RawMessage) (json.RawMessage, []metadatamodel.MetadataDefinitionValidationIssue, error) {
			if resourceType != "action" || resourceKey != "create_order" {
				t.Fatalf("validator received unnormalized identity: %q %q", resourceType, resourceKey)
			}
			return json.RawMessage(`{"normalized":true}`), nil, nil
		})
	if err != nil {
		t.Fatalf("validate definition: %v", err)
	}
	if !result.Valid || string(result.NormalizedPayload) != `{"normalized":true}` {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestValidateDefinitionRequestMapsOwnerErrorsToFieldIssues(t *testing.T) {
	admin := identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, metadatacontract.MetadataActionDefinitionValidate)}}
	result, err := MetadataValidateDefinitionRequest(t.Context(), "field", "order.customer", json.RawMessage(`{}`), admin,
		func(context.Context, string, string, json.RawMessage) (json.RawMessage, []metadatamodel.MetadataDefinitionValidationIssue, error) {
			return nil, nil, badRequest("backend.metadata.relation_target_required")
		})
	if err != nil {
		t.Fatalf("validate definition: %v", err)
	}
	if result.Valid || len(result.Errors) != 1 || result.Errors[0].FieldPath != "validation.target" {
		t.Fatalf("unexpected validation failure: %+v", result)
	}
}

func TestValidateDefinitionRequestRejectsNonAdminBeforePayloadValidation(t *testing.T) {
	called := false
	_, err := MetadataValidateDefinitionRequest(t.Context(), "action", "create_order", json.RawMessage(`{}`), identitymodel.Principal{},
		func(context.Context, string, string, json.RawMessage) (json.RawMessage, []metadatamodel.MetadataDefinitionValidationIssue, error) {
			called = true
			return nil, nil, nil
		})
	if err == nil || called {
		t.Fatalf("expected authorization failure before payload validation: err=%v called=%v", err, called)
	}
}
