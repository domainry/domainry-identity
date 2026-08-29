package identity

import (
	"database/sql"
	"sort"
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func identityID(parts ...string) string {
	value := strings.Join(parts, "_")
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, "/", "_")
	return value
}

func nullableString(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return *value
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func pointerFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	out := value.String
	return &out
}

func valueFromNull(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nowString() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloneIdentityRole(role identitymodel.IdentityRole) identitymodel.IdentityRole {
	return role
}

func cloneIdentityRoleRequest(request identitymodel.IdentityRoleRequest) identitymodel.IdentityRoleRequest {
	request.RoleIDs = append([]string(nil), request.RoleIDs...)
	return request
}
