package projection

import (
	"sort"
	"strings"
	"time"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func IdentityBuildAccessReverseIndex(roles []identitymodel.IdentityRole, definitions []identitymodel.RoleSchema, assignments []identitymodel.IdentityUserRoleAssignment) identitymodel.IdentityAccessReverseIndex {
	index := identitymodel.IdentityAccessReverseIndex{
		UserRoles: map[string][]string{}, RolePermissions: map[string][]string{},
		PermissionRoles: map[string][]string{}, ObjectActionRoles: map[string][]string{},
	}
	roleKeyByID := map[string]string{}
	for _, role := range roles {
		key := strings.TrimSpace(role.Key)
		if key == "" {
			key = strings.TrimSpace(role.ID)
		}
		roleKeyByID[role.ID] = key
	}
	for _, assignment := range assignments {
		if assignment.Status != "" && assignment.Status != string(identitymodel.IdentityStatusActive) {
			continue
		}
		if key := roleKeyByID[assignment.RoleID]; key != "" {
			index.UserRoles[assignment.UserID] = append(index.UserRoles[assignment.UserID], key)
		}
	}
	for _, role := range definitions {
		roleKey := strings.TrimSpace(role.Key)
		for _, grant := range role.Permissions {
			permission := strings.TrimSpace(grant.PermissionKey)
			if permission == "" || !grant.DataScope.Valid() {
				continue
			}
			index.RolePermissions[roleKey] = append(index.RolePermissions[roleKey], permission)
			index.PermissionRoles[permission] = append(index.PermissionRoles[permission], roleKey)
			objectKey, action := identityProjectionPermissionParts(permission)
			if objectKey != "" && action != "" {
				index.ObjectActionRoles[objectKey+"."+action] = append(index.ObjectActionRoles[objectKey+"."+action], roleKey)
			}
		}
	}
	identityProjectionNormalizeStringMap(index.UserRoles)
	identityProjectionNormalizeStringMap(index.RolePermissions)
	identityProjectionNormalizeStringMap(index.PermissionRoles)
	identityProjectionNormalizeStringMap(index.ObjectActionRoles)
	return index
}

func IdentityBuildGovernanceReports(now time.Time, permissions []identitymodel.IdentityPermissionDefinition, roles []identitymodel.IdentityRole, definitions []identitymodel.RoleSchema, assignments []identitymodel.IdentityUserRoleAssignment) identitymodel.IdentityGovernanceReports {
	report := identitymodel.IdentityGovernanceReports{
		OrphanPermissions: []string{}, RolesWithoutMembers: []string{}, ExpiredEntitlements: []identitymodel.IdentityUserRoleAssignment{},
		UnboundAssignments: []identitymodel.IdentityUserRoleAssignment{}, AuthorizationDrift: []string{},
	}
	roleByID := map[string]identitymodel.IdentityRole{}
	definitionByKey := map[string]identitymodel.RoleSchema{}
	permissionByKey := make(map[string]identitymodel.IdentityPermissionDefinition, len(permissions))
	grantedPermissions := map[string]bool{}
	memberRoleIDs := map[string]bool{}
	for _, role := range roles {
		roleByID[role.ID] = role
	}
	for _, permission := range permissions {
		if key := strings.TrimSpace(permission.Key); key != "" {
			permissionByKey[key] = permission
		}
	}
	for _, definition := range definitions {
		roleKey := strings.TrimSpace(definition.Key)
		definitionByKey[roleKey] = definition
		for _, grant := range definition.Permissions {
			permissionKey := strings.TrimSpace(grant.PermissionKey)
			if permissionKey == "" {
				continue
			}
			grantedPermissions[permissionKey] = true
			permission, exists := permissionByKey[permissionKey]
			switch {
			case !exists:
				report.AuthorizationDrift = append(report.AuthorizationDrift, "role:"+roleKey+":permission:"+permissionKey+":unknown")
			case permission.DefinitionStatus != identitymodel.IdentityPermissionDefinitionActive:
				report.AuthorizationDrift = append(report.AuthorizationDrift, "role:"+roleKey+":permission:"+permissionKey+":retired")
			case !permission.Enabled:
				report.AuthorizationDrift = append(report.AuthorizationDrift, "role:"+roleKey+":permission:"+permissionKey+":disabled")
			}
		}
	}
	for _, assignment := range assignments {
		role, roleExists := roleByID[assignment.RoleID]
		if !roleExists {
			report.AuthorizationDrift = append(report.AuthorizationDrift, "assignment:"+assignment.UserID+":"+assignment.RoleID+":unknown_role")
		} else if _, published := definitionByKey[identityProjectionRoleKey(role)]; !published {
			report.AuthorizationDrift = append(report.AuthorizationDrift, "assignment:"+assignment.UserID+":"+assignment.RoleID+":unpublished_role")
		}
		if identityProjectionAssignmentExpired(assignment, now) {
			report.ExpiredEntitlements = append(report.ExpiredEntitlements, assignment)
			continue
		}
		if assignment.Status == "" || assignment.Status == string(identitymodel.IdentityStatusActive) {
			memberRoleIDs[assignment.RoleID] = true
		}
		if (strings.TrimSpace(assignment.BindingKey) == "") != (strings.TrimSpace(assignment.ProfileID) == "") {
			report.UnboundAssignments = append(report.UnboundAssignments, assignment)
		}
	}
	for _, permission := range permissions {
		if key := strings.TrimSpace(permission.Key); key != "" && !grantedPermissions[key] {
			report.OrphanPermissions = append(report.OrphanPermissions, key)
		}
	}
	for _, role := range roles {
		if !memberRoleIDs[role.ID] {
			report.RolesWithoutMembers = append(report.RolesWithoutMembers, identityProjectionRoleKey(role))
		}
	}
	report.OrphanPermissions = identityProjectionUniqueStrings(report.OrphanPermissions)
	report.RolesWithoutMembers = identityProjectionUniqueStrings(report.RolesWithoutMembers)
	report.AuthorizationDrift = identityProjectionUniqueStrings(report.AuthorizationDrift)
	sort.Slice(report.ExpiredEntitlements, func(left, right int) bool {
		return identityProjectionAssignmentKey(report.ExpiredEntitlements[left]) < identityProjectionAssignmentKey(report.ExpiredEntitlements[right])
	})
	sort.Slice(report.UnboundAssignments, func(left, right int) bool {
		return identityProjectionAssignmentKey(report.UnboundAssignments[left]) < identityProjectionAssignmentKey(report.UnboundAssignments[right])
	})
	report.UnboundAssignments = identityProjectionUniqueAssignments(report.UnboundAssignments)
	return report
}

func IdentityPreviewRoleChange(request identitymodel.IdentityRoleChangeImpactRequest, current identitymodel.RoleSchema, projectionRole identitymodel.IdentityRole, assignments []identitymodel.IdentityUserRoleAssignment, objects []definitionmodel.ObjectSchema, actions []definitionmodel.ActionSchema) identitymodel.IdentityRoleChangeImpact {
	impact := identitymodel.IdentityRoleChangeImpact{RoleKey: strings.TrimSpace(request.RoleKey)}
	if impact.RoleKey == "" {
		impact.RoleKey = strings.TrimSpace(request.Role.Key)
	}
	affectedUsers := map[string]bool{}
	profileTypes := []string{}
	for _, assignment := range assignments {
		if assignment.RoleID != projectionRole.ID || assignment.Status != "" && assignment.Status != string(identitymodel.IdentityStatusActive) {
			continue
		}
		affectedUsers[assignment.UserID] = true
		if assignment.BindingKey != "" {
			profileTypes = append(profileTypes, "business_profile:"+assignment.BindingKey)
		}
		if assignment.BindingKey == "" {
			profileTypes = append(profileTypes, "account")
		}
	}
	impact.AffectedUserCount = len(affectedUsers)
	impact.ProfileTypes = identityProjectionUniqueStrings(profileTypes)
	impact.AddedPermissions = identityProjectionStringDifference(identitymodel.RolePermissionKeys(request.Role.Permissions), identitymodel.RolePermissionKeys(current.Permissions))
	impact.RemovedPermissions = identityProjectionStringDifference(identitymodel.RolePermissionKeys(current.Permissions), identitymodel.RolePermissionKeys(request.Role.Permissions))
	for _, permission := range append(append([]string(nil), impact.AddedPermissions...), impact.RemovedPermissions...) {
		objectKey, action := identityProjectionPermissionParts(permission)
		impact.AffectedObjects = append(impact.AffectedObjects, objectKey)
		impact.AffectedActions = append(impact.AffectedActions, permission)
		for _, runtimeAction := range actions {
			if strings.TrimSpace(runtimeAction.Key) == permission &&
				(strings.TrimSpace(runtimeAction.RiskLevel) == "high" || strings.TrimSpace(runtimeAction.RiskLevel) == "critical" ||
					identitycontract.IdentityActionApprovalRequired(runtimeAction) || len(identitycontract.IdentityActionAssuranceMethods(runtimeAction)) > 0) {
				impact.HighRiskCapabilities = append(impact.HighRiskCapabilities, runtimeAction.Key)
			}
		}
		if action == "" {
			continue
		}
		for _, object := range objects {
			if object.Key != objectKey {
				continue
			}
			for _, field := range object.Fields {
				if identityProjectionSensitiveField(object, field) {
					impact.SensitiveFields = append(impact.SensitiveFields, object.Key+"."+field.Key)
				}
			}
		}
	}
	impact.AffectedObjects = identityProjectionUniqueStrings(impact.AffectedObjects)
	impact.AffectedActions = identityProjectionUniqueStrings(impact.AffectedActions)
	impact.SensitiveFields = identityProjectionUniqueStrings(impact.SensitiveFields)
	impact.HighRiskCapabilities = identityProjectionUniqueStrings(impact.HighRiskCapabilities)
	return impact
}

func identityProjectionNormalizeStringMap(values map[string][]string) {
	for key, items := range values {
		values[key] = identityProjectionUniqueStrings(items)
	}
}

func identityProjectionRoleKey(role identitymodel.IdentityRole) string {
	if key := strings.TrimSpace(role.Key); key != "" {
		return key
	}
	return strings.TrimSpace(role.ID)
}

func identityProjectionAssignmentExpired(assignment identitymodel.IdentityUserRoleAssignment, now time.Time) bool {
	for _, value := range []string{assignment.ValidUntil, identityProjectionExpiresAt(assignment)} {
		if value = strings.TrimSpace(value); value != "" {
			if parsed, err := time.Parse(time.RFC3339, value); err != nil || !now.Before(parsed) {
				return true
			}
		}
	}
	return false
}

func identityProjectionExpiresAt(assignment identitymodel.IdentityUserRoleAssignment) string {
	if assignment.ExpiresAt == nil {
		return ""
	}
	return *assignment.ExpiresAt
}

func identityProjectionStringDifference(left, right []string) []string {
	excluded := map[string]bool{}
	for _, value := range right {
		excluded[strings.TrimSpace(value)] = true
	}
	out := []string{}
	for _, value := range left {
		if value = strings.TrimSpace(value); value != "" && !excluded[value] {
			out = append(out, value)
		}
	}
	return identityProjectionUniqueStrings(out)
}

func identityProjectionUniqueAssignments(values []identitymodel.IdentityUserRoleAssignment) []identitymodel.IdentityUserRoleAssignment {
	out := make([]identitymodel.IdentityUserRoleAssignment, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		key := identityProjectionAssignmentKey(value)
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}
