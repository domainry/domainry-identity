package metadata

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
)

type metadataWorkspaceAuthorizationProbe struct {
	metadatarepository.MetadataRepository
	calls *int
}

func (p metadataWorkspaceAuthorizationProbe) LoadManifest(context.Context, identitymodel.SystemScope) (manifestmodel.ManifestSchema, error) {
	*p.calls++
	return manifestmodel.ManifestSchema{}, nil
}

func TestMetadataApplicationAuthorizesWorkspaceBeforeRepositoryAccess(t *testing.T) {
	calls := 0
	service := NewMetadataApplicationService(MetadataApplicationDependencies{Repository: metadataWorkspaceAuthorizationProbe{calls: &calls}})
	principal := identitymodel.Principal{Known: true, Role: identitymodel.RoleSchema{Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
		metadatacontract.MetadataActionMigrationPlanGet,
		metadatacontract.MetadataActionReload,
	)}}
	checks := []func() error{
		func() error { _, err := service.MetadataMigrationPlan(t.Context(), principal); return err },
		func() error { _, err := service.ReloadMetadata(t.Context(), principal); return err },
	}
	for index, check := range checks {
		if code := apperror.CodeOf(check()); code != "backend.workspace_scope_required" {
			t.Fatalf("check %d code=%q", index, code)
		}
	}
	if calls != 0 {
		t.Fatalf("repository called before workspace authorization: %d", calls)
	}
}
