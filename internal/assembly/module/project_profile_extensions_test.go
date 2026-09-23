package moduleassembly

import (
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityassembly "github.com/domainry/domainry-identity/internal/assembly"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

func TestProjectProfileExtensionPublisherOverlaysSourceMetadataAndDeepCopies(t *testing.T) {
	metadata := identityassembly.NewMetadataRuntime(metadataservice.SchemaSnapshotState{IdentityProfileExtensions: []identitymodel.IdentityProfileExtension{
		{ObjectKey: "employee_profile", IdentityRelationField: "old_identity_user_id", BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "employee"}},
		{ObjectKey: "identity_owned_profile", IdentityRelationField: "identity_user_id", BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "identity_owned"}},
	}})
	binding := &moduleBinding{runtime: &identityassembly.Core{MetadataRuntime: metadata}}
	source := []identitysdk.ProjectProfileExtension{{
		ObjectKey: "employee_profile", IdentityRelationField: "identity_user_id", Cardinality: "one_to_one",
		BusinessIdentity: identitysdk.ProjectBusinessIdentityBinding{Key: "employee", ActiveStatusValues: []string{"active"}, Claims: []identitysdk.ProjectProfileClaimBinding{{ClaimKey: "store_code", FieldKey: "store_code"}}},
		BindingLifecycle: identitysdk.ProjectProfileBindingLifecycle{InvitationChannels: []string{"email"}, ClaimProofs: []identitysdk.ProjectProfileClaimProof{{Type: "field", FieldKey: "employee_no"}}, RebindRevokesSessions: true},
	}}
	if err := binding.ProjectProfileExtensionPublisher().PublishProjectProfileExtensions(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	source[0].BusinessIdentity.ActiveStatusValues[0] = "disabled"
	schema := metadata.Schema()
	if len(schema.IdentityProfileExtensions) != 2 || schema.IdentityProfileExtensions[0].ObjectKey != "employee_profile" || schema.IdentityProfileExtensions[1].ObjectKey != "identity_owned_profile" {
		t.Fatalf("extensions=%#v", schema.IdentityProfileExtensions)
	}
	published := schema.IdentityProfileExtensions[0]
	if published.IdentityRelationField != "identity_user_id" || published.BusinessIdentity.ActiveStatusValues[0] != "active" || published.BusinessIdentity.Claims[0].FieldKey != "store_code" || published.BindingLifecycle.ClaimProofs[0].FieldKey != "employee_no" {
		t.Fatalf("published=%#v", published)
	}
	if schema.IdentityProfileExtensions[1].BusinessIdentity.Key != "identity_owned" {
		t.Fatalf("source-owned extension was lost: %#v", schema.IdentityProfileExtensions[1])
	}
	if err := binding.ProjectProfileExtensionPublisher().PublishProjectProfileExtensions(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if restored := metadata.Schema().IdentityProfileExtensions; len(restored) != 2 || restored[0].IdentityRelationField != "old_identity_user_id" {
		t.Fatalf("project overlay was not replaceable: %#v", restored)
	}
}

func TestProjectProfileExtensionPublisherRejectsDuplicateObjects(t *testing.T) {
	metadata := identityassembly.NewMetadataRuntime(metadataservice.SchemaSnapshotState{})
	binding := &moduleBinding{runtime: &identityassembly.Core{MetadataRuntime: metadata}}
	err := binding.ProjectProfileExtensionPublisher().PublishProjectProfileExtensions(t.Context(), []identitysdk.ProjectProfileExtension{{ObjectKey: "employee_profile"}, {ObjectKey: " employee_profile "}})
	if err == nil || len(metadata.Schema().IdentityProfileExtensions) != 0 {
		t.Fatalf("duplicate publication error=%v schema=%#v", err, metadata.Schema().IdentityProfileExtensions)
	}
}
