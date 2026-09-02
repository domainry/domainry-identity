package projection

import (
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"

	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-foundation/apperror"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
)

func IdentityBuildFeaturePermissions(objects []definitionmodel.ObjectSchema, actions []definitionmodel.ActionSchema, principal identitymodel.Principal) (identitycontract.IdentityFeaturePermissionSnapshot, error) {
	if !principal.Known {
		return identitycontract.IdentityFeaturePermissionSnapshot{}, &apperror.AppError{Kind: apperror.KindForbidden, Code: "backend.role.unknown"}
	}
	result := identitycontract.IdentityFeaturePermissionSnapshot{
		RoleKey:   principal.Role.Key,
		UserID:    principal.UserID,
		Objects:   make([]identitycontract.IdentityFeatureObjectPermissions, 0, len(objects)),
		Actions:   make([]identitycontract.IdentityFeatureActionPermission, 0, len(actions)),
		Functions: functionPermissionSnapshots(principal),
		Data:      make([]identitycontract.IdentityDataScopePermission, 0, len(objects)),
		Fields:    []identitycontract.IdentityFieldPermissionSnapshot{},
		Exports:   make([]identitycontract.IdentityExportPermissionSnapshot, 0, len(objects)),
	}
	for _, object := range objects {
		item := identitycontract.IdentityFeatureObjectPermissions{ObjectKey: object.Key}
		for _, action := range []string{"read", "create", "update", "delete", "import", "export"} {
			item.Actions = append(item.Actions, objectFeatureDecision(principal, object.Key, action))
		}
		result.Objects = append(result.Objects, item)
		result.Data = append(result.Data, dataScopePermission(principal, object))
		result.Fields = append(result.Fields, fieldPermissionSnapshots(principal, object)...)
		result.Exports = append(result.Exports, exportPermissionSnapshot(principal, object))
	}
	for _, action := range actions {
		permissionKey := strings.TrimSpace(action.Key)
		objectKey, permissionAction := splitPermission(permissionKey)
		if objectKey == "" {
			objectKey = action.ObjectKey
		}
		if permissionAction == "" {
			permissionAction = actionName(action)
		}
		decision := objectFeatureDecision(principal, objectKey, permissionAction)
		decision.Key = action.Key
		decision.PermissionKey = permissionKey
		result.Actions = append(result.Actions, identitycontract.IdentityFeatureActionPermission{
			Key:               action.Key,
			ObjectKey:         action.ObjectKey,
			Label:             action.Label,
			Kind:              action.Kind,
			PermissionKey:     permissionKey,
			DataScope:         decision.DataScope,
			Allowed:           decision.Allowed,
			Reason:            decision.Reason,
			AssuranceRequired: actionAssuranceRequired(action),
		})
	}
	sort.Slice(result.Actions, func(i, j int) bool { return result.Actions[i].Key < result.Actions[j].Key })
	return result, nil
}

func actionAssuranceRequired(action definitionmodel.ActionSchema) []string {
	if action.AssurancePolicy == nil {
		return []string{}
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(action.AssurancePolicy.RequiredMethods))
	for _, method := range action.AssurancePolicy.RequiredMethods {
		method = strings.TrimSpace(method)
		if method == "" {
			continue
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		result = append(result, method)
	}
	sort.Strings(result)
	return result
}

func functionPermissionSnapshots(principal identitymodel.Principal) []identitycontract.IdentityFeatureFunctionPermission {
	seen := map[string]struct{}{}
	out := make([]identitycontract.IdentityFeatureFunctionPermission, 0, len(principal.Role.Permissions))
	appendPermission := func(permissionKey, reason string) {
		if _, ok := seen[permissionKey]; ok {
			return
		}
		seen[permissionKey] = struct{}{}
		out = append(out, identitycontract.IdentityFeatureFunctionPermission{
			Key: permissionKey,
			Decision: identitycontract.IdentityFeaturePermissionDecision{
				Key:           permissionKey,
				PermissionKey: permissionKey,
				Allowed:       true,
				Reason:        reason,
			},
		})
	}
	for _, permissionKey := range principal.Role.Permissions {
		permissionKey = strings.TrimSpace(permissionKey)
		if permissionKey == "" {
			continue
		}
		appendPermission(permissionKey, "allowed")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func objectFeatureDecision(principal identitymodel.Principal, objectKey string, action string) identitycontract.IdentityFeaturePermissionDecision {
	permissionKey := strings.TrimSpace(objectKey) + "." + strings.TrimSpace(action)
	dataScope := identitycontract.IdentityDataScopeForAction(principal.Role, objectKey, action)
	decision := identitycontract.IdentityFeaturePermissionDecision{
		Key:           permissionKey,
		ObjectKey:     strings.TrimSpace(objectKey),
		Action:        strings.TrimSpace(action),
		PermissionKey: permissionKey,
		DataScope:     dataScope,
		Allowed:       false,
		Reason:        "missing_permission",
	}
	if !principal.Known {
		decision.Reason = "role_unknown"
		return decision
	}
	if !identitycontract.IdentityRoleAllows(principal.Role, objectKey, action) {
		return decision
	}
	if !identitycontract.IdentityRoleAllowsData(principal.Role, objectKey, action) {
		decision.Reason = "missing_data_permission"
		return decision
	}
	decision.Allowed = true
	decision.Reason = "allowed"
	return decision
}

func dataScopePermission(principal identitymodel.Principal, object definitionmodel.ObjectSchema) identitycontract.IdentityDataScopePermission {
	return identitycontract.IdentityDataScopePermission{
		ObjectKey:  object.Key,
		OwnerField: "owner_user_id",
		OrgIDField: "owner_org_id",
		Context: identitycontract.IdentityDataScopeContext{
			OrgID:                 principal.OrgID,
			OrgScopeIDs:           append([]string(nil), principal.OrgScopeIDs...),
			SupportOrgID:          principal.SupportOrgID,
			SupportOrgScopeIDs:    append([]string(nil), principal.SupportOrgScopeIDs...),
			ReportingScopeUserIDs: append([]string(nil), principal.ReportingScopeUserIDs...),
		},
		Policy: dataScopeDecision(principal, object.Key),
	}
}

func dataScopeDecision(principal identitymodel.Principal, objectKey string) identitycontract.IdentityDataScopeDecision {
	scope := identitycontract.IdentityDataScope(principal.Role, objectKey)
	decision := identitycontract.IdentityDataScopeDecision{
		Scope:     scope,
		Predicate: dataPredicateForRole(principal.Role, objectKey),
		Allowed:   false,
		Reason:    "missing_data_permission",
	}
	if !principal.Known {
		decision.Reason = "role_unknown"
		return decision
	}
	if scope == "none" {
		return decision
	}
	if isAllScopeName(scope) {
		decision.Allowed = true
		decision.Reason = "allowed"
		return decision
	}
	if isOwnedScopeName(scope) {
		if strings.TrimSpace(principal.UserID) == "" {
			decision.Reason = "missing_user"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "allowed"
		return decision
	}
	if isOrganizationScopeName(scope) {
		if strings.TrimSpace(principal.OrgID) == "" {
			decision.Reason = "missing_org"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "allowed"
		return decision
	}
	if isOrganizationAndChildrenScopeName(scope) {
		if len(principal.OrgScopeIDs) == 0 {
			decision.Reason = "missing_org_scope_ids"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "allowed"
		return decision
	}
	if isSelfAndSubordinatesScopeName(scope) {
		if len(principal.ReportingScopeUserIDs) == 0 {
			decision.Reason = "missing_reporting_scope_user_ids"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "allowed"
		return decision
	}
	if scope == "custom" {
		if decision.Predicate == nil {
			decision.Reason = "missing_predicate"
			return decision
		}
		if identityPredicateUsesActorClaim(*decision.Predicate, "support_org_scope_ids") && len(principal.SupportOrgScopeIDs) == 0 {
			decision.Reason = "missing_support_org_scope_ids"
			return decision
		}
		decision.Allowed = true
		decision.Reason = "allowed"
		return decision
	}
	if strings.TrimSpace(scope) == "none" {
		return decision
	}
	decision.Reason = "unsupported_scope"
	return decision
}

func dataPredicateForRole(role identitymodel.RoleSchema, objectKey string) *identitymodel.IdentityPolicyExpression {
	for _, permission := range role.DataPermissions {
		if permission.ObjectKey != objectKey {
			continue
		}
		return permission.Predicate
	}
	return nil
}

func identityPredicateUsesActorClaim(expression identitymodel.IdentityPolicyExpression, claimKey string) bool {
	if strings.EqualFold(strings.TrimSpace(expression.ValueSource), "actor_claim") && strings.EqualFold(strings.TrimSpace(expression.ClaimKey), claimKey) {
		return true
	}
	for _, child := range expression.Children {
		if identityPredicateUsesActorClaim(child, claimKey) {
			return true
		}
	}
	return false
}

func isAllScopeName(scope string) bool {
	scope = strings.TrimSpace(scope)
	return scope == "all_records"
}

func isOwnedScopeName(scope string) bool {
	scope = strings.TrimSpace(scope)
	return scope == "owned_records"
}

func isOrganizationScopeName(scope string) bool {
	return strings.TrimSpace(scope) == "organization"
}

func isOrganizationAndChildrenScopeName(scope string) bool {
	scope = strings.TrimSpace(scope)
	return scope == "organization_and_children"
}

func isSelfAndSubordinatesScopeName(scope string) bool {
	return strings.TrimSpace(scope) == "self_and_subordinates"
}

func fieldPermissionSnapshots(principal identitymodel.Principal, object definitionmodel.ObjectSchema) []identitycontract.IdentityFieldPermissionSnapshot {
	out := make([]identitycontract.IdentityFieldPermissionSnapshot, 0, len(object.Fields))
	for _, field := range object.Fields {
		if field.DisabledAt != "" {
			continue
		}
		out = append(out, fieldPermissionSnapshot(principal.Role, object, field))
	}
	return out
}

func fieldPermissionSnapshot(role identitymodel.RoleSchema, object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema) identitycontract.IdentityFieldPermissionSnapshot {
	source := "default"
	permission, explicit := explicitFieldPermission(role, object.Key, field.Key)
	if explicit {
		source = "explicit"
	}
	return identitycontract.IdentityFieldPermissionSnapshot{
		ObjectKey: object.Key,
		FieldKey:  field.Key,
		FieldType: field.Type,
		Read:      fieldAccessDecision(identitycontract.IdentityCanReadObjectField(role, object, field), permission.Reason),
		Write:     fieldAccessDecision(identitycontract.IdentityCanWriteObjectField(role, object, field), permission.Reason),
		Export:    fieldAccessDecision(identitycontract.IdentityCanExportObjectField(role, object, field), permission.Reason),
		Masked:    identitycontract.IdentityFieldReadMasked(role, object.Key, field.Key),
		Source:    source,
	}
}

func explicitFieldPermission(role identitymodel.RoleSchema, objectKey string, fieldKey string) (identitymodel.FieldPermission, bool) {
	var merged identitymodel.FieldPermission
	found := false
	for _, permission := range role.FieldPermissions {
		if permission.ObjectKey == objectKey && permission.FieldKey == fieldKey {
			if !found {
				merged = permission
				merged.Policies = nil
				merged.Masked = true
			}
			found = true
			merged.Read = merged.Read || permission.Read
			merged.Write = merged.Write || permission.Write
			merged.Export = merged.Export || permission.Export
			if (permission.Read || permission.Export) && !permission.Masked {
				merged.Masked = false
			}
			merged.Policies = append(merged.Policies, permission.Policies...)
			if merged.Reason == "" {
				merged.Reason = permission.Reason
			}
		}
	}
	return merged, found
}

func fieldAccessDecision(allowed bool, reason string) identitycontract.IdentityFieldAccessDecision {
	if allowed {
		return identitycontract.IdentityFieldAccessDecision{Allowed: true, Reason: "allowed"}
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "field_permission_denied"
	}
	return identitycontract.IdentityFieldAccessDecision{Allowed: false, Reason: reason}
}

func exportPermissionSnapshot(principal identitymodel.Principal, object definitionmodel.ObjectSchema) identitycontract.IdentityExportPermissionSnapshot {
	decision := objectFeatureDecision(principal, object.Key, "export")
	fields := make([]identitycontract.IdentityExportFieldPermission, 0, len(object.Fields))
	for _, field := range object.Fields {
		if field.DisabledAt != "" {
			continue
		}
		permission, _ := explicitFieldPermission(principal.Role, object.Key, field.Key)
		fields = append(fields, identitycontract.IdentityExportFieldPermission{
			FieldKey:  field.Key,
			FieldType: field.Type,
			Export:    fieldAccessDecision(identitycontract.IdentityCanExportField(principal.Role, object.Key, field.Key), permission.Reason),
			Masked:    identitycontract.IdentityFieldExportMasked(principal.Role, object.Key, field.Key),
		})
	}
	return identitycontract.IdentityExportPermissionSnapshot{
		ObjectKey: object.Key,
		Allowed:   decision.Allowed,
		Reason:    decision.Reason,
		DataScope: decision.DataScope,
		Fields:    fields,
	}
}

func permissionProjectionStringValue(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func valueOrDefault(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func splitPermission(value string) (string, string) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) < 2 {
		return "", strings.TrimSpace(value)
	}
	return strings.TrimSpace(parts[len(parts)-2]), strings.TrimSpace(parts[len(parts)-1])
}

func actionName(action definitionmodel.ActionSchema) string {
	_, name := splitPermission(action.Key)
	return name
}
