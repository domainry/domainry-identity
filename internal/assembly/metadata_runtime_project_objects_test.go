package assembly

import (
	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	metadataservice "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

func TestMetadataRuntimeComposesProjectObjectsWithoutReplacingIdentityObjects(t *testing.T) {
	runtime := NewMetadataRuntime(metadataservice.SchemaSnapshotState{Objects: []definitionmodel.ObjectSchema{{Key: "identity_user", Fields: []definitionmodel.FieldSchema{{Key: "email"}}}}})
	runtime.ReplaceProjectObjects([]definitionmodel.ObjectSchema{
		{Key: "customer", Fields: []definitionmodel.FieldSchema{{Key: "name"}}},
		{Key: "identity_user", Fields: []definitionmodel.FieldSchema{{Key: "application_override"}}},
	})
	objects := runtime.EffectiveAccessObjects()
	if len(objects) != 2 || objects[0].Key != "customer" || objects[1].Key != "identity_user" {
		t.Fatalf("objects=%#v", objects)
	}
	if len(objects[1].Fields) != 1 || objects[1].Fields[0].Key != "email" {
		t.Fatalf("Identity-owned object was replaced: %#v", objects[1])
	}
	if schema := runtime.Schema(); len(schema.Objects) != 1 || schema.Objects[0].Key != "identity_user" {
		t.Fatalf("project catalog polluted Identity metadata: %#v", schema.Objects)
	}

	runtime.ReplaceProjectObjects(nil)
	objects = runtime.EffectiveAccessObjects()
	if len(objects) != 1 || objects[0].Key != "identity_user" {
		t.Fatalf("project catalog was not replaceable: %#v", objects)
	}
}
