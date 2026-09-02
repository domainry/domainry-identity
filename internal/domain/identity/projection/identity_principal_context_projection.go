package projection

import (
	"sort"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func IdentityBuildPrincipalContext(principal identitymodel.Principal) identitymodel.IdentityPrincipalContext {
	context := identitymodel.IdentityPrincipalContext{
		ContractVersion:       identitymodel.IdentityPrincipalContextContractV1,
		Known:                 principal.Known,
		WorkspaceID:           strings.TrimSpace(principal.WorkspaceID),
		UserID:                strings.TrimSpace(principal.UserID),
		RoleKey:               strings.TrimSpace(principal.Role.Key),
		AuthorizationRevision: strings.TrimSpace(principal.AuthorizationRevision),
		OrgID:                 strings.TrimSpace(principal.OrgID),
		OrganizationPath:      strings.TrimSpace(principal.OrganizationPath),
		SurfaceKey:            strings.TrimSpace(principal.SurfaceKey),
		BusinessProfiles:      []identitymodel.IdentityPrincipalBusinessProfileContext{},
		RequestContexts:       []identitymodel.IdentityPrincipalRequestContext{},
	}
	if !principal.Known {
		return context
	}
	baseHeaders := identityPrincipalWorkspaceHeaders(context.WorkspaceID)
	context.RequestContexts = append(context.RequestContexts, identitymodel.IdentityPrincipalRequestContext{
		Key: "identity", SubjectKind: "identity", CanonicalRequestHeader: baseHeaders,
	})
	profiles := append([]identitymodel.BusinessProfileReference(nil), principal.BusinessProfiles...)
	sort.Slice(profiles, func(left, right int) bool {
		return identityPrincipalBusinessProfileKey(profiles[left]) < identityPrincipalBusinessProfileKey(profiles[right])
	})
	for _, profile := range profiles {
		bindingKey := strings.TrimSpace(profile.BindingKey)
		recordID := strings.TrimSpace(profile.RecordID)
		surfaces := identityPrincipalUniqueStrings(profile.SurfaceKeys)
		active := principal.ActiveBusinessProfile != nil &&
			strings.TrimSpace(principal.ActiveBusinessProfile.BindingKey) == bindingKey &&
			strings.TrimSpace(principal.ActiveBusinessProfile.RecordID) == recordID
		context.BusinessProfiles = append(context.BusinessProfiles, identitymodel.IdentityPrincipalBusinessProfileContext{
			BindingKey: bindingKey, ObjectKey: strings.TrimSpace(profile.ObjectKey), RecordID: recordID, SurfaceKeys: surfaces, Active: active,
		})
		requestSurfaces := append([]string{""}, surfaces...)
		for _, surface := range requestSurfaces {
			headers := identityPrincipalWorkspaceHeaders(context.WorkspaceID)
			headers["X-Business-Profile-Key"] = bindingKey
			headers["X-Business-Profile-ID"] = recordID
			if surface != "" {
				headers["X-Surface-Key"] = surface
			}
			key := strings.Join([]string{"business_profile", bindingKey, recordID, valueOrUnderscore(surface)}, "/")
			context.RequestContexts = append(context.RequestContexts, identitymodel.IdentityPrincipalRequestContext{
				Key: key, SubjectKind: "business_profile", SurfaceKey: surface,
				BusinessProfileKey: bindingKey, BusinessProfileID: recordID, CanonicalRequestHeader: headers,
			})
		}
	}
	return context
}

func identityPrincipalWorkspaceHeaders(workspaceID string) map[string]string {
	headers := map[string]string{}
	if workspaceID != "" {
		headers["X-Workspace-ID"] = workspaceID
	}
	return headers
}

func identityPrincipalUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func identityPrincipalBusinessProfileKey(profile identitymodel.BusinessProfileReference) string {
	return strings.Join([]string{strings.TrimSpace(profile.BindingKey), strings.TrimSpace(profile.RecordID), strings.TrimSpace(profile.ObjectKey)}, "\x00")
}

func valueOrUnderscore(value string) string {
	if strings.TrimSpace(value) == "" {
		return "_"
	}
	return strings.TrimSpace(value)
}
