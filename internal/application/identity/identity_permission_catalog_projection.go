package identity

import (
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"strings"

	localization "github.com/domainry/domainry-identity/internal/platform/localization"
)

var identityLocalizationLookup = localization.Lookup

func IdentityPermissionsFromRoles(roles []identitymodel.RoleSchema, objects []definitionmodel.ObjectSchema, locale string) []identitymodel.IdentityPermissionDefinition {
	return IdentityPermissionsFromRuntime(roles, objects, nil, locale)
}

func IdentityPermissionsFromRuntime(roles []identitymodel.RoleSchema, objects []definitionmodel.ObjectSchema, actions []definitionmodel.ActionSchema, locale string) []identitymodel.IdentityPermissionDefinition {
	seen := map[string]bool{}
	indexes := map[string]int{}
	out := []identitymodel.IdentityPermissionDefinition{}
	for _, permission := range []identitymodel.IdentityPermissionDefinition{
		{Key: "workspace.admin", Label: localization.T(locale, "permission.workspace_admin"), System: "workspace", Resource: "admin", Category: localization.T(locale, "system.permission_category"), Action: "manage"},
		{Key: "identity.permission.configure", Label: localization.T(locale, "permission.identity_configure"), System: "identity", Resource: "permission", Category: localization.T(locale, "system.permission_category"), Action: "configure"},
		{Key: "identity.security.read", Label: "Account security read", System: "identity", Resource: "security", Category: localization.T(locale, "system.permission_category"), Action: "read"},
		{Key: "identity.security.write", Label: "Account security manage", System: "identity", Resource: "security", Category: localization.T(locale, "system.permission_category"), Action: "write"},
		{Key: "identity.profile_binding.manage", Label: "Business profile binding manage", System: "identity", Resource: "profile_binding", Category: localization.T(locale, "system.permission_category"), Action: "manage"},
	} {
		seen[permission.Key] = true
		out = append(out, permission)
		indexes[permission.Key] = len(out) - 1
	}
	for _, object := range objects {
		if strings.TrimSpace(object.Key) == "" || objectIsSystemOwned(object) {
			continue
		}
		for _, action := range []string{"create", "read", "update", "delete"} {
			key := object.Key + "." + action
			if seen[key] {
				continue
			}
			seen[key] = true
			resourceLabel := identityPermissionResourceLabel(locale, objects, object.Key)
			actionLabel := identityPermissionActionLabel(locale, action)
			out = append(out, identitymodel.IdentityPermissionDefinition{
				Key:           key,
				Label:         strings.Join(nonEmptyStrings(resourceLabel, actionLabel), " · "),
				System:        object.Key,
				Resource:      object.Key,
				ResourceLabel: resourceLabel,
				Action:        action,
				Category:      identityPermissionCategoryLabel(locale, object.Key, resourceLabel),
				Description:   strings.Join(nonEmptyStrings(resourceLabel, actionLabel), " · "),
			})
			indexes[key] = len(out) - 1
		}
	}
	for _, runtimeAction := range actions {
		key := strings.TrimSpace(runtimeAction.RequiresPermission)
		if key == "" {
			continue
		}
		usage := identityActionPermissionUsage(runtimeAction)
		if seen[key] {
			index := indexes[key]
			out[index].ActionUsages = append(out[index].ActionUsages, usage)
			continue
		}
		seen[key] = true
		system, resource, action := IdentityParsePermissionKey(key)
		resourceLabel := identityPermissionResourceLabel(locale, objects, resource)
		actionLabel := identityPermissionActionLabel(locale, action)
		permission := identitymodel.IdentityPermissionDefinition{
			Key: key, Label: strings.Join(nonEmptyStrings(resourceLabel, actionLabel), " · "), System: system,
			Resource: resource, ResourceLabel: resourceLabel, Action: action,
			Category:    identityPermissionCategoryLabel(locale, system, resourceLabel),
			Description: strings.Join(nonEmptyStrings(identityPermissionSystemLabel(locale, system), resourceLabel, actionLabel), " · "),
		}
		applyActionPermissionMetadata(&permission, runtimeAction)
		permission.ActionUsages = append(permission.ActionUsages, usage)
		out = append(out, permission)
		indexes[key] = len(out) - 1
	}
	for _, role := range roles {
		for _, key := range role.Permissions {
			key = strings.TrimSpace(key)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			if permission, ok := platformIdentityPermissionDefinition(locale, objects, key); ok {
				out = append(out, permission)
				indexes[key] = len(out) - 1
				continue
			}
			system, resource, action := IdentityParsePermissionKey(key)
			resourceLabel := identityPermissionResourceLabel(locale, objects, resource)
			actionLabel := identityPermissionActionLabel(locale, action)
			systemLabel := identityPermissionSystemLabel(locale, system)
			categoryLabel := identityPermissionCategoryLabel(locale, system, resourceLabel)
			permission := identitymodel.IdentityPermissionDefinition{
				Key:           key,
				Label:         strings.Join(nonEmptyStrings(resourceLabel, actionLabel), " · "),
				System:        system,
				Resource:      resource,
				ResourceLabel: resourceLabel,
				Action:        action,
				Category:      categoryLabel,
				Description:   strings.Join(nonEmptyStrings(systemLabel, resourceLabel, actionLabel), " · "),
			}
			out = append(out, permission)
			indexes[key] = len(out) - 1
		}
	}
	return out
}

func identityActionPermissionUsage(action definitionmodel.ActionSchema) identitymodel.IdentityActionPermissionUsage {
	return identitymodel.IdentityActionPermissionUsage{
		ActionKey:             strings.TrimSpace(action.Key),
		ObjectKey:             strings.TrimSpace(action.ObjectKey),
		ActionLabel:           strings.TrimSpace(action.Label),
		AuthorizationStrategy: identitycontract.IdentityActionAuthorizationStrategy(action),
		RiskLevel:             identitycontract.IdentityActionRiskLevel(action),
		ApprovalRequired:      identitycontract.IdentityActionApprovalRequired(action),
		AssuranceRequired:     append([]string(nil), identitycontract.IdentityActionAssuranceMethods(action)...),
		LifecycleStatus:       "active",
	}
}

func applyActionPermissionMetadata(permission *identitymodel.IdentityPermissionDefinition, action definitionmodel.ActionSchema) {
	permission.SourceType = "business_action"
	permission.SourceActionKey = strings.TrimSpace(action.Key)
	permission.ObjectKey = strings.TrimSpace(action.ObjectKey)
	permission.ActionLabel = strings.TrimSpace(action.Label)
	permission.AuthorizationStrategy = identitycontract.IdentityActionAuthorizationStrategy(action)
	permission.RiskLevel = identitycontract.IdentityActionRiskLevel(action)
	permission.AssuranceRequired = append([]string(nil), identitycontract.IdentityActionAssuranceMethods(action)...)
	permission.ApprovalRequired = identitycontract.IdentityActionApprovalRequired(action)
	permission.LifecycleStatus = "active"
}

func objectIsSystemOwned(object definitionmodel.ObjectSchema) bool {
	value, ok := object.Config["system_object"]
	return ok && value == true
}

func platformIdentityPermissionDefinition(locale string, objects []definitionmodel.ObjectSchema, key string) (identitymodel.IdentityPermissionDefinition, bool) {
	system := ""
	resource := ""
	action := ""
	switch {
	case key == "workspace.admin":
		system = "platform"
		resource = "workspace"
		action = "admin"
	case key == "identity.permission.configure":
		system = "platform"
		resource = "identity_permission"
		action = "configure"
	case strings.HasPrefix(key, "identity_"):
		system, resource, action = IdentityParsePermissionKey(key)
		if action == "" {
			return identitymodel.IdentityPermissionDefinition{}, false
		}
	case strings.HasPrefix(key, "platform."):
		parts := strings.Split(key, ".")
		if len(parts) < 3 {
			return identitymodel.IdentityPermissionDefinition{}, false
		}
		system = "platform"
		resource = parts[1]
		action = strings.Join(parts[2:], ".")
	default:
		return identitymodel.IdentityPermissionDefinition{}, false
	}
	resourceLabel := identityPlatformPermissionResourceLabel(locale, objects, resource)
	actionLabel := identityPermissionActionLabel(locale, action)
	label := identityPlatformPermissionLabel(locale, key)
	if label == "" {
		label = strings.Join(nonEmptyStrings(resourceLabel, actionLabel), " · ")
	}
	return identitymodel.IdentityPermissionDefinition{
		Key:           key,
		Label:         label,
		System:        system,
		Resource:      resource,
		ResourceLabel: resourceLabel,
		Action:        action,
		Category:      identityPermissionCategoryLabel(locale, system, resourceLabel),
		Description:   strings.Join(nonEmptyStrings(identityPermissionSystemLabel(locale, system), resourceLabel, actionLabel), " · "),
	}, true
}

func IdentityParsePermissionKey(key string) (string, string, string) {
	parts := strings.Split(strings.TrimSpace(key), ".")
	switch len(parts) {
	case 1:
		return "domain", parts[0], ""
	case 2:
		return "domain", parts[0], parts[1]
	default:
		return parts[0], parts[1], strings.Join(parts[2:], ".")
	}
}

func identityPlatformPermissionLabel(locale string, key string) string {
	normalized := strings.NewReplacer(".", "_", "-", "_").Replace(strings.TrimSpace(key))
	if normalized == "" {
		return ""
	}
	for _, candidate := range []string{"permission." + normalized, "permission." + strings.TrimPrefix(normalized, "platform_")} {
		if label := i18nLookup(locale, candidate); label != "" {
			return label
		}
	}
	return ""
}

func identityPlatformPermissionResourceLabel(locale string, objects []definitionmodel.ObjectSchema, resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return ""
	}
	for _, key := range []string{"permission.resource." + resource, "module." + resource, "object." + resource, "menu." + resource} {
		if label := i18nLookup(locale, key); label != "" {
			return label
		}
	}
	for _, object := range objects {
		if object.Key == resource {
			return identityProjectionValueOrDefault(object.Name, IdentityHumanizeIdentifier(resource))
		}
	}
	return IdentityHumanizeIdentifier(resource)
}

func identityPermissionResourceLabel(locale string, objects []definitionmodel.ObjectSchema, resource string) string {
	if resource == "" {
		return ""
	}
	if label := i18nLookup(locale, "permission.resource."+resource); label != "" {
		return label
	}
	if label := i18nLookup(locale, "object."+resource); label != "" {
		return label
	}
	if label := i18nLookup(locale, "menu."+resource); label != "" {
		return label
	}
	if label := i18nLookup(locale, "module."+resource); label != "" {
		return label
	}
	for _, object := range objects {
		if object.Key == resource {
			return localizedIdentityFallbackLabel(locale, object.Key, identityProjectionValueOrDefault(object.Name, IdentityHumanizeIdentifier(resource)))
		}
	}
	return localizedIdentityFallbackLabel(locale, resource, IdentityHumanizeIdentifier(resource))
}

func identityPermissionActionLabel(locale string, action string) string {
	if action == "" {
		return ""
	}
	if label := i18nLookup(locale, "action."+action); label != "" {
		return label
	}
	return IdentityHumanizeIdentifier(action)
}

func identityPermissionSystemLabel(locale string, system string) string {
	if label := i18nLookup(locale, "system."+system); label != "" {
		return label
	}
	switch system {
	case "platform", "workspace", "identity":
		return localization.T(locale, "system.permission_category")
	case "domain":
		return localization.T(locale, "system.business_permission_category")
	default:
		return IdentityHumanizeIdentifier(system)
	}
}

func identityPermissionCategoryLabel(locale string, system string, resourceLabel string) string {
	if system == "platform" || system == "workspace" || system == "identity" {
		return localization.T(locale, "system.permission_category")
	}
	return identityProjectionValueOrDefault(resourceLabel, localization.T(locale, "system.business_permission_category"))
}

func localizedIdentityFallbackLabel(locale string, key string, fallback string) string {
	if locale != "zh-CN" {
		return fallback
	}
	localizationKey := ""
	switch strings.TrimSpace(key) {
	case "identity_data_scope_policy":
		localizationKey = "identity.dataScopePolicy"
	case "identity_field_permission":
		localizationKey = "identity.fieldPermission"
	case "identity_permission":
		localizationKey = "identity.permission"
	case "identity_role":
		localizationKey = "identity.role"
	case "identity_role_permission_assignment":
		localizationKey = "object.identity_role_permission_assignment"
	case "identity_user_role_assignment":
		localizationKey = "object.identity_user_role_assignment"
	case "identity_user":
		localizationKey = "identity.user"
	case "identity_department":
		localizationKey = "identity.department"
	}
	if label := i18nLookup(locale, localizationKey); label != "" {
		return label
	}
	return fallback
}

func i18nLookup(locale string, key string) string {
	if value, ok := identityLocalizationLookup(locale, key); ok && strings.TrimSpace(value) != "" {
		return value
	}
	return ""
}

func IdentityHumanizeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	value = strings.ReplaceAll(value, ".", " ")
	return strings.Title(value)
}

func identityProjectionValueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func nonEmptyStrings(values ...string) []string {
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
