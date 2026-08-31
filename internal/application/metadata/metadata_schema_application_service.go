package metadata

import (
	"context"
	"strings"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityprojection "github.com/domainry/domainry-identity/internal/domain/identity/projection"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
	metadatadomain "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

func (s *MetadataApplicationService) CurrentManifest(ctx context.Context, principal identitymodel.Principal) (manifestmodel.ManifestSchema, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return manifestmodel.ManifestSchema{}, forbidden("auth.permission_denied")
	}
	manifest, err := s.repository.LoadManifest(ctx, metadataInstallationScope("load current Runtime manifest for global validation"))
	return manifest, wrapMetadataError(err)
}

type MetadataSchemaApplicationService struct {
	*metadatadomain.MetadataSchemaDomainService
}

type MetadataSchemaProvider interface {
	SchemaForPrincipal(context.Context, identitymodel.Principal) metadatamodel.MetadataSchemaSnapshot
}

func NewMetadataSchemaApplicationService(schema MetadataSchemaProvider, repository metadatarepository.MetadataRepository) *MetadataSchemaApplicationService {
	return &MetadataSchemaApplicationService{MetadataSchemaDomainService: metadatadomain.NewMetadataSchemaDomainService(schema, repository)}
}

func (s *MetadataSchemaApplicationService) FeaturePermissions(ctx context.Context, principal identitymodel.Principal) (identitycontract.IdentityFeaturePermissionSnapshot, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return identitycontract.IdentityFeaturePermissionSnapshot{}, err
	}
	snapshot := s.Snapshot(ctx)
	return identityprojection.IdentityBuildFeaturePermissions(snapshot.Objects, snapshot.Actions, principal)
}

func (s *MetadataApplicationService) ReloadMetadata(ctx context.Context, principal identitymodel.Principal) (metadatamodel.MetadataSchemaSnapshot, error) {
	if err := metadataAuthorizeCommand(principal); err != nil {
		return metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return metadatamodel.MetadataSchemaSnapshot{}, forbidden("auth.permission_denied")
	}
	manifest, err := s.repository.LoadManifest(ctx, metadataInstallationScope("reload metadata manifest"))
	if err != nil {
		return metadatamodel.MetadataSchemaSnapshot{}, err
	}
	if err := s.repository.SyncManifest(ctx, metadataInstallationScope("synchronize metadata manifest"), manifest); err != nil {
		return metadatamodel.MetadataSchemaSnapshot{}, wrapMetadataError(err)
	}
	s.runtime.ApplyManifestMetadata(valueOrDefault(manifest.TemplateID, s.templateID), valueOrDefault(manifest.Version, s.version), valueOrDefault(manifest.Name, s.name), manifest.Objects, manifest.Actions, manifest.Roles, manifest.PermissionSets, manifest.PermissionSetGroups, manifest.Guardrails, manifest.IdentityProfileExtensions)
	snapshot := s.runtime.Schema()
	s.notifyReloadObservers(snapshot)
	return snapshot, nil
}

func (s *MetadataApplicationService) MetadataMigrationPlan(ctx context.Context, principal identitymodel.Principal) ([]metadatamodel.MetadataMigrationStep, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return nil, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return nil, forbidden("auth.permission_denied")
	}
	manifest, err := s.repository.LoadManifest(ctx, metadataInstallationScope("load metadata migration manifest"))
	if err != nil {
		return nil, err
	}
	steps, err := s.repository.MigrationPlan(ctx, metadataInstallationScope("plan metadata migration"), manifest)
	return steps, wrapMetadataError(err)
}

// MetadataObjectRecordCount exposes only the aggregate needed to validate
// Schema changes. It deliberately bypasses business record data scopes so a
// metadata administrator never has to receive record payloads merely to decide
// whether a required field needs a default value.
func (s *MetadataApplicationService) MetadataObjectRecordCount(ctx context.Context, objectKey string, principal identitymodel.Principal) (int, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return 0, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "metadata.read") {
		return 0, forbidden("auth.permission_denied")
	}
	objectKey = strings.TrimSpace(objectKey)
	var objectFound bool
	for _, candidate := range s.runtime.Schema().Objects {
		if candidate.Key == objectKey {
			objectFound = true
			break
		}
	}
	if !objectFound {
		return 0, notFound("backend.metadata.object_not_found", "object", objectKey)
	}
	// Identity owns the authorization metadata catalog, not the business data
	// store. A host Runtime may perform its own data-compatibility preflight;
	// the standalone Identity service never reads business records.
	return 0, nil
}

func (s *MetadataApplicationService) LocalizedTextsForLocale(ctx context.Context, workspaceID, locale string) ([]metadatamodel.LocalizedText, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if err := metadataAuthorizeWorkspaceQuery(workspaceID); err != nil {
		return nil, err
	}
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return nil, nil
	}
	values, err := s.repository.ListLocalizedTexts(ctx, workspaceID, metadatamodel.LocalizedTextQuery{WorkspaceID: workspaceID, Locale: locale})
	return values, wrapMetadataError(err)
}
