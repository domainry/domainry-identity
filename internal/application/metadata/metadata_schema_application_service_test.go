package metadata

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

type metadataSchemaApplicationProviderStub struct {
	snapshot metadatamodel.MetadataSchemaSnapshot
}

func (s metadataSchemaApplicationProviderStub) SchemaForPrincipal(context.Context, identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot {
	return s.snapshot
}

func TestMetadataSchemaApplicationServiceOwnsFeaturePermissionProjection(t *testing.T) {
	application := NewMetadataSchemaApplicationService(metadataSchemaApplicationProviderStub{snapshot: metadatamodel.MetadataSchemaSnapshot{Objects: []definitionmodel.ObjectSchema{{Key: "customer", Name: "Customer"}}}}, nil)
	admin := identitymodel.Principal{Known: true, WorkspaceID: "workspace-primary", UserID: "admin", Role: identitymodel.RoleSchema{
		Permissions:     []string{"customer.read"},
		DataPermissions: []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records", Read: true}},
	}}
	permissions, err := application.FeaturePermissions(t.Context(), admin)
	if err != nil || len(permissions.Objects) != 1 || !permissions.Objects[0].Actions[0].Allowed {
		t.Fatalf("permissions=%#v err=%v", permissions, err)
	}
	if _, err := application.FeaturePermissions(t.Context(), identitymodel.Principal{}); apperror.CodeOf(err) != "backend.workspace_scope_required" {
		t.Fatalf("unknown principal error=%v", err)
	}
}
