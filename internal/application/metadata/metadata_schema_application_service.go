package metadata

import (
	"context"
	"strings"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identityprojection "github.com/domainry/domainry-identity/internal/domain/identity/projection"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	metadatacontract "github.com/domainry/domainry-identity/internal/domain/metadata/contract"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadatarepository "github.com/domainry/domainry-identity/internal/domain/metadata/repository"
	metadatadomain "github.com/domainry/domainry-identity/internal/domain/metadata/service"
)

func (s *MetadataApplicationService) CurrentManifest(ctx context.Context, principal identitymodel.Principal) (manifestmodel.ManifestSchema, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return manifestmodel.ManifestSchema{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionManifestGet) {
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
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionReload) {
		return metadatamodel.MetadataSchemaSnapshot{}, forbidden("auth.permission_denied")
	}
	if s == nil || s.repository == nil || s.runtime == nil {
		return metadatamodel.MetadataSchemaSnapshot{}, metadataInternalError("reload metadata")
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	current := s.runtime.Schema()
	manifest, err := s.repository.LoadManifest(ctx, metadataInstallationScope("reload metadata manifest"))
	if err != nil {
		return current, err
	}
	if err := s.repository.SyncManifest(ctx, metadataInstallationScope("synchronize metadata manifest"), manifest); err != nil {
		return current, wrapMetadataError(err)
	}
	candidate := metadatadomain.BuildSchemaSnapshot(metadatadomain.SchemaSnapshotState{
		TemplateID: valueOrDefault(manifest.TemplateID, s.templateID), TemplateVersion: valueOrDefault(manifest.Version, s.version), Name: valueOrDefault(manifest.Name, s.name),
		Objects: manifest.Objects, Actions: manifest.Actions, Roles: manifest.Roles,
		PermissionSets: manifest.PermissionSets, PermissionSetGroups: manifest.PermissionSetGroups,
		Guardrails: manifest.Guardrails, IdentityProfileExtensions: manifest.IdentityProfileExtensions,
	})
	commits, err := s.prepareReloadObservers(ctx, candidate)
	if err != nil {
		return current, err
	}
	s.runtime.ActivateMetadata(candidate)
	for _, commit := range commits {
		commit()
	}
	return candidate, nil
}

func (s *MetadataApplicationService) MetadataMigrationPlan(ctx context.Context, principal identitymodel.Principal) ([]metadatamodel.MetadataMigrationStep, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return nil, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionMigrationPlanGet) {
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
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, metadatacontract.MetadataActionObjectRecordCountGet) {
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
