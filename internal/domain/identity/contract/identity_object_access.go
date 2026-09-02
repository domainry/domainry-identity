package contract

import (
	"fmt"
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

func identityContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
