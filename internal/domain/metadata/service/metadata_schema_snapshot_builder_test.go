package service

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"testing"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
)

func TestBuildSchemaSnapshotCanonicalizesOwnerProjection(t *testing.T) {
	snapshot := BuildSchemaSnapshot(SchemaSnapshotState{
		TemplateID: "template", TemplateVersion: "1",
		Objects: []definitionmodel.ObjectSchema{{Key: "z"}, {Key: "a"}},
		Actions: []definitionmodel.ActionSchema{{Key: "z.run", ObjectKey: "z"}, {Key: "a.run", ObjectKey: "a"}},
		Roles:   []identitymodel.RoleSchema{{Key: "z"}, {Key: "a"}},
	})
	if snapshot.Objects[0].Key != "a" || snapshot.Actions[0].Key != "a.run" || snapshot.Roles[0].Key != "a" {
		t.Fatalf("snapshot is not canonical: %#v", snapshot)
	}
	if snapshot.SchemaHash == "" || snapshot.SnapshotVersion != snapshot.SchemaHash {
		t.Fatalf("snapshot hash is incomplete: %#v", snapshot)
	}
}
