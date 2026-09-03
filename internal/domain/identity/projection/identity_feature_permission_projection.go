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
		Fields:    []identitycontract.IdentityFieldPermissionSnapshot{},
		Exports:   make([]identitycontract.IdentityExportPermissionSnapshot, 0, len(objects)),
	}
	for _, object := range objects {
		item := identitycontract.IdentityFeatureObjectPermissions{ObjectKey: object.Key}
		for _, action := range []string{"read", "create", "update", "delete", "import", "export"} {
			item.Actions = append(item.Actions, objectFeatureDecision(principal, object.Key, action))
		}
		result.Objects = append(result.Objects, item)
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
			DataScopes:        decision.DataScopes,
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
	for _, permission := range principal.Role.Permissions {
		permissionKey := strings.TrimSpace(permission.PermissionKey)
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
	dataScopes := identitycontract.IdentityDataScopesForAction(principal.Role, objectKey, action)
	decision := identitycontract.IdentityFeaturePermissionDecision{
		Key:           permissionKey,
		ObjectKey:     strings.TrimSpace(objectKey),
		Action:        strings.TrimSpace(action),
		PermissionKey: permissionKey,
		DataScopes:    dataScopes,
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
		decision.Reason = "missing_data_scope"
		return decision
	}
	decision.Allowed = true
	decision.Reason = "allowed"
	return decision
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
		ObjectKey:  object.Key,
		Allowed:    decision.Allowed,
		Reason:     decision.Reason,
		DataScopes: decision.DataScopes,
		Fields:     fields,
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
