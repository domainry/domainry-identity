package service

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *AuthDomainService) authUser(user identitymodel.IdentityUser) authmodel.AuthUser {
	locale := strings.TrimSpace(user.Locale)
	if s.normalizeLocale != nil {
		locale = s.normalizeLocale(locale)
	}
	if _, supported := s.supportedLocales[locale]; !supported {
		locale = s.defaultLocale
	}
	version := user.Version
	if version < 1 {
		version = 1
	}
	return authmodel.AuthUser{
		ID:      user.ID,
		Name:    user.Name,
		Email:   user.Email,
		Locale:  locale,
		Version: version,
		Status:  user.Status,
	}
}

func authRoles(roles []identitymodel.IdentityRole) []authmodel.AuthRole {
	out := make([]authmodel.AuthRole, 0, len(roles))
	for _, role := range roles {
		out = append(out, authmodel.AuthRole{ID: role.ID, Key: role.Key, Label: role.Label})
	}
	return out
}

func defaultAuthRole(roles []identitymodel.IdentityRole) string {
	if len(roles) == 0 {
		return ""
	}
	for _, preferredKey := range []string{"admin", "platform_admin", "erp_admin", "sales_admin", "menu_admin", "owner", "manager"} {
		for _, role := range roles {
			if role.Key == preferredKey || role.ID == preferredKey {
				return role.Key
			}
		}
	}
	for _, role := range roles {
		if !systemManagementRole(role.Key) {
			return role.Key
		}
	}
	return roles[0].Key
}

func systemManagementRole(roleKey string) bool {
	roleKey = strings.ToLower(strings.TrimSpace(roleKey))
	return strings.HasPrefix(roleKey, "identity_") ||
		strings.HasPrefix(roleKey, "platform_") ||
		strings.HasPrefix(roleKey, "pipeline_")
}
