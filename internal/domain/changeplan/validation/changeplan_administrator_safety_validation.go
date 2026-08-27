package validation

import changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"

import (
	"strings"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (validator *businessChangePlanValidator) validateAdministratorSafety(itemIndex int, item changeplanmodel.BusinessSystemChangeItem) {
	if businessReferenceResourceType(item.ResourceType) != "role" || (item.Operation != "update" && item.Operation != "archive" && item.Operation != "delete") {
		return
	}
	role, exists := validator.snapshotRole(item.ResourceKey)
	if !exists || !identityRoleHasPermission(role, "workspace.admin") {
		return
	}
	removesAdministrator := item.Operation == "archive" || item.Operation == "delete" || !flattenBusinessChangeStrings(businessChangeJSONValue(item.After))["workspace.admin"]
	if removesAdministrator && validator.activeAdministratorUsersExcept(role.Key) == 0 {
		validator.issue(item.ItemID, changePlanIndexPath(itemIndex, "after"), "backend.change_plan.unique_admin_required", "role", role.Key)
	}
}

func (validator *businessChangePlanValidator) snapshotRole(key string) (identitymodel.RoleSchema, bool) {
	for _, role := range validator.snapshot.IdentityGovernance.RoleDefinitions {
		if role.Key == key {
			return role, true
		}
	}
	return identitymodel.RoleSchema{}, false
}

func (validator *businessChangePlanValidator) activeAdministratorUsersExcept(excludedRoleKey string) int {
	administratorRoles := map[string]bool{}
	administratorKeys := map[string]bool{}
	for _, role := range validator.snapshot.IdentityGovernance.RoleDefinitions {
		if role.Key != excludedRoleKey && identityRoleHasPermission(role, "workspace.admin") {
			administratorKeys[role.Key] = true
		}
	}
	for _, role := range validator.snapshot.IdentityGovernance.Roles {
		if role.Status != identitymodel.IdentityStatusDisabled && role.Status != identitymodel.IdentityStatusDeleted && administratorKeys[role.Key] {
			administratorRoles[role.ID] = true
		}
	}
	activeUsers := map[string]bool{}
	for _, user := range validator.snapshot.IdentityGovernance.Users {
		if user.Status != identitymodel.IdentityStatusDisabled && user.Status != identitymodel.IdentityStatusDeleted {
			activeUsers[user.ID] = true
		}
	}
	now := time.Now().UTC()
	users := map[string]bool{}
	for _, assignment := range validator.snapshot.IdentityGovernance.UserRoleAssignments {
		if !administratorRoles[assignment.RoleID] || !activeUsers[assignment.UserID] || identityAssignmentExpired(assignment.ExpiresAt, now) {
			continue
		}
		users[assignment.UserID] = true
	}
	return len(users)
}

func identityRoleHasPermission(role identitymodel.RoleSchema, permission string) bool {
	for _, candidate := range role.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}

func identityAssignmentExpired(expiresAt *string, now time.Time) bool {
	if expiresAt == nil || strings.TrimSpace(*expiresAt) == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*expiresAt))
	return err != nil || !parsed.After(now)
}
