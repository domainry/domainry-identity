package metadata

import (
	"context"
	"strings"

	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	metadataprojection "github.com/domainry/domainry-identity/internal/domain/metadata/projection"
)

func (s *MetadataApplicationService) LocalizedTextCoverage(ctx context.Context, locale string, fallbackLocale string, principal identitymodel.Principal) (metadatamodel.LocalizedTextCoverageResult, error) {
	if err := metadataAuthorizeQuery(principal); err != nil {
		return metadatamodel.LocalizedTextCoverageResult{}, err
	}
	if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, "workspace.admin") {
		return metadatamodel.LocalizedTextCoverageResult{}, forbidden("auth.permission_denied")
	}
	workspaceID := strings.TrimSpace(principal.WorkspaceID)
	locale = strings.TrimSpace(locale)
	if locale == "" {
		return metadatamodel.LocalizedTextCoverageResult{}, badRequest("metadata.localized_texts.locale_required")
	}
	fallbackLocale = strings.TrimSpace(fallbackLocale)
	if fallbackLocale == locale {
		fallbackLocale = ""
	}
	values, err := s.repository.ListLocalizedTexts(ctx, workspaceID, metadatamodel.LocalizedTextQuery{WorkspaceID: workspaceID})
	if err != nil {
		return metadatamodel.LocalizedTextCoverageResult{}, wrapMetadataError(err)
	}
	return metadataprojection.MetadataLocalizedTextCoverage(workspaceID, locale, fallbackLocale, s.runtime.Schema(), values), nil
}
