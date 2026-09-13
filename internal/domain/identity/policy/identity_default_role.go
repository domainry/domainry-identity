package policy

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"strings"
)

// SelectDefaultRole picks a deterministic presentation role from the caller's
// already qualified roles. Role names carry no built-in authority or priority.
func SelectDefaultRole(roles []identitymodel.IdentityRole) string {
	selected := ""
	for _, role := range roles {
		key := strings.TrimSpace(role.Key)
		if key != "" && (selected == "" || key < selected) {
			selected = key
		}
	}
	return selected
}
