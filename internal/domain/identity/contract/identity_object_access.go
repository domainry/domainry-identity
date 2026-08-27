package contract

import (
	"fmt"
	"strconv"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func IdentityCanReadObjectField(role identitymodel.RoleSchema, object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema) bool {
	return identityCanAccessObjectField(role, object, field, "read")
}

func IdentityCanWriteObjectField(role identitymodel.RoleSchema, object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema) bool {
	return identityCanAccessObjectField(role, object, field, "update")
}

func IdentityCanExportObjectField(role identitymodel.RoleSchema, object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema) bool {
	return identityCanAccessObjectField(role, object, field, "export")
}

func identityCanAccessObjectField(role identitymodel.RoleSchema, object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema, action string) bool {
	if IdentityRoleGuardrailDeniesField(role, object.Key, field.Key, action) {
		return false
	}
	explicit, allowed := false, false
	for _, permission := range role.FieldPermissions {
		if permission.ObjectKey != object.Key || permission.FieldKey != field.Key && permission.FieldKey != "*" {
			continue
		}
		explicit = true
		switch action {
		case "update":
			allowed = allowed || permission.Write
		case "export":
			allowed = allowed || permission.Export
		default:
			allowed = allowed || permission.Read
		}
	}
	if explicit {
		return allowed
	}
	if identityFieldRequiresExplicitAccess(object, field) {
		return false
	}
	switch action {
	case "update":
		return IdentityCanWriteField(role, object.Key, field.Key)
	case "export":
		return IdentityCanExportField(role, object.Key, field.Key)
	default:
		return IdentityCanReadField(role, object.Key, field.Key)
	}
}

func IdentityCanReadField(role identitymodel.RoleSchema, objectKey, fieldKey string) bool {
	return identityFieldAccess(role, objectKey, fieldKey, "read")
}

func IdentityCanWriteField(role identitymodel.RoleSchema, objectKey, fieldKey string) bool {
	return identityFieldAccess(role, objectKey, fieldKey, "update")
}

func identityFieldAccess(role identitymodel.RoleSchema, objectKey, fieldKey, action string) bool {
	if IdentityRoleGuardrailDeniesField(role, objectKey, fieldKey, action) {
		return false
	}
	if IdentityRoleAllows(role, "workspace", "admin") {
		return true
	}
	found := false
	for _, permission := range role.FieldPermissions {
		if permission.ObjectKey != objectKey || permission.FieldKey != fieldKey && permission.FieldKey != "*" {
			continue
		}
		found = true
		if action == "update" && permission.Write || action == "read" && permission.Read {
			return true
		}
	}
	return !found
}

func IdentityCanExportField(role identitymodel.RoleSchema, objectKey, fieldKey string) bool {
	if IdentityRoleGuardrailDeniesField(role, objectKey, fieldKey, "export") {
		return false
	}
	if IdentityRoleAllows(role, "workspace", "admin") {
		return true
	}
	if len(role.ExportRules) > 0 {
		allowedByRule := false
		for _, rule := range role.ExportRules {
			if rule.ObjectKey == objectKey && (len(rule.Fields) == 0 || identityContains(rule.Fields, fieldKey)) {
				allowedByRule = true
				break
			}
		}
		if !allowedByRule {
			return false
		}
	}
	found := false
	for _, permission := range role.FieldPermissions {
		if permission.ObjectKey == objectKey && (permission.FieldKey == fieldKey || permission.FieldKey == "*") {
			found = true
			if permission.Export {
				return true
			}
		}
	}
	return !found
}

func IdentityFieldReadMasked(role identitymodel.RoleSchema, objectKey, fieldKey string) bool {
	return identityFieldMasked(role, objectKey, fieldKey, false)
}

func IdentityFieldExportMasked(role identitymodel.RoleSchema, objectKey, fieldKey string) bool {
	return identityFieldMasked(role, objectKey, fieldKey, true)
}

func identityFieldMasked(role identitymodel.RoleSchema, objectKey, fieldKey string, export bool) bool {
	if IdentityRoleAllows(role, "workspace", "admin") {
		return false
	}
	foundAllowed := false
	for _, permission := range role.FieldPermissions {
		if permission.ObjectKey != objectKey || permission.FieldKey != fieldKey && permission.FieldKey != "*" {
			continue
		}
		allowed := permission.Read
		if export {
			allowed = permission.Export
		}
		if !allowed {
			continue
		}
		foundAllowed = true
		if !permission.Masked {
			return false
		}
	}
	return foundAllowed
}

func identityFieldRequiresExplicitAccess(object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema) bool {
	if strings.TrimSpace(fmt.Sprint(object.Config["field_access_mode"])) == "default_deny" {
		return true
	}
	if sensitive, ok := field.Config["sensitive"].(bool); ok && sensitive {
		return true
	}
	switch strings.TrimSpace(fmt.Sprint(field.Config["sensitivity"])) {
	case "sensitive", "secret", "credential", "security_raw", "key_material":
		return true
	default:
		return false
	}
}

func IdentityObjectOwnerFieldKey(object definitionmodel.ObjectSchema) string {
	if explicit := identityConfiguredField(object, "scope_owner"); explicit != "" {
		return explicit
	}
	if strings.TrimSpace(fmt.Sprint(object.UX["kind"])) == "identity_profile_extension" {
		if config, ok := object.UX["config"].(map[string]any); ok {
			key := strings.TrimSpace(fmt.Sprint(config["identity_relation_field"]))
			for _, field := range object.Fields {
				if field.Key == key && field.Type == "relation" {
					return key
				}
			}
		}
	}
	for _, preferred := range []string{"owner", "assignee", "requester", "created_by", "createdBy"} {
		for _, field := range object.Fields {
			if field.Key == preferred && field.Type == "user" {
				return field.Key
			}
		}
	}
	for _, field := range object.Fields {
		if field.Type == "user" {
			return field.Key
		}
	}
	return ""
}

func IdentityObjectDepartmentPathFieldKey(object definitionmodel.ObjectSchema) string {
	if key := identityConfiguredField(object, "scope_organization_path"); key != "" {
		return key
	}
	return identityFirstField(object, "owner_department_path", "ownerDepartmentPath")
}

func IdentityObjectDepartmentIDFieldKey(object definitionmodel.ObjectSchema) string {
	if key := identityConfiguredField(object, "scope_organization_id"); key != "" {
		return key
	}
	return identityFirstField(object, "owner_department_id", "ownerDepartmentId")
}

func IdentityObjectTeamFieldKey(object definitionmodel.ObjectSchema) string {
	return identityFirstField(object, "team", "team_id", "owner_team", "owner_team_id", "assigned_team")
}

func IdentityObjectStoreFieldKey(object definitionmodel.ObjectSchema) string {
	return identityFirstField(object, "store", "store_id", "store_profile", "store_profile_id", "owner_store", "owner_store_id")
}

func IdentityObjectTerritoryFieldKey(object definitionmodel.ObjectSchema) string {
	return identityFirstField(object, "territory", "territory_id", "territory_owner", "owner_territory", "owner_territory_id")
}

func IdentityObjectWarehouseFieldKey(object definitionmodel.ObjectSchema) string {
	return identityFirstField(object, "warehouse", "warehouse_id", "receiving_warehouse", "to_warehouse", "owner_warehouse", "owner_warehouse_id")
}

func identityConfiguredField(object definitionmodel.ObjectSchema, configKey string) string {
	for _, field := range object.Fields {
		if enabled, valid := identityBool(field.Config[configKey]); valid && enabled {
			return field.Key
		}
	}
	return ""
}

func identityFirstField(object definitionmodel.ObjectSchema, candidates ...string) string {
	for _, candidate := range candidates {
		for _, field := range object.Fields {
			if field.Key == candidate {
				return field.Key
			}
		}
	}
	return ""
}

func identityBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func identityContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
