package changeplan

import (
	"fmt"
	"strings"

	changeplanprojection "github.com/domainry/domainry-identity/internal/domain/changeplan/projection"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type ReferenceSchema struct {
	Objects         []definitionmodel.ObjectSchema
	Views           []definitionmodel.ViewSchema
	Actions         []definitionmodel.ActionSchema
	Roles           []identitymodel.RoleSchema
	ProfileBindings []identitymodel.IdentityProfileExtension
}

func AddSchemaReferences(builder *changeplanprojection.ChangePlanReferenceGraphBuilder, snapshot ReferenceSchema) {
	for _, object := range snapshot.Objects {
		builder.Node("object", object.Key, object.Key, object.Name, "")
		for _, field := range object.Fields {
			fieldKey := object.Key + "." + field.Key
			builder.Node("field", fieldKey, object.Key, field.Name, "")
			builder.Edge("field", fieldKey, "object", object.Key, "belongs_to", "fields."+field.Key)
			if target := referenceRelationTarget(field); target != "" {
				builder.Edge("field", fieldKey, "object", target, "relation_target", "validation.target")
			}
		}
	}
	for _, view := range snapshot.Views {
		builder.Node("view", view.Key, view.ObjectKey, view.Name, "")
		builder.Edge("view", view.Key, "object", view.ObjectKey, "reads_object", "object_key")
	}
}

func AddIdentityReferences(builder *changeplanprojection.ChangePlanReferenceGraphBuilder, snapshot ReferenceSchema) {
	for _, role := range snapshot.Roles {
		builder.Node("role", role.Key, "", role.Name, "")
		for index, permission := range role.Permissions {
			path := fmt.Sprintf("permissions[%d]", index)
			assignmentKey := role.Key + ":" + permission
			builder.Node("role_permission", assignmentKey, "", permission, "identity")
			builder.Edge("role_permission", assignmentKey, "role", role.Key, "belongs_to_role", "role_key")
			builder.Edge("role_permission", assignmentKey, "permission", permission, "grants_permission", path)
			grant := identitymodel.RoleSchema{Permissions: []string{permission}}
			for _, action := range snapshot.Actions {
				if identitycontract.IdentityRoleHasPermissionKey(grant, strings.TrimSpace(action.RequiresPermission)) {
					builder.Edge("role_permission", assignmentKey, "action", action.Key, "authorizes_action", path)
				}
			}
		}
		for index, permission := range role.DataPermissions {
			path := fmt.Sprintf("data_permissions[%d]", index)
			builder.Edge("role", role.Key, "object", permission.ObjectKey, "scopes_object", path+".object_key")
			addIdentityPolicyReferences(builder, role.Key, permission.ObjectKey, permission.Predicate, path+".predicate")
		}
		for index, permission := range role.FieldPermissions {
			path := fmt.Sprintf("field_permissions[%d]", index)
			builder.Edge("role", role.Key, "field", permission.ObjectKey+"."+permission.FieldKey, "governs_field", path+".field_key")
			for policyIndex, policy := range permission.Policies {
				addIdentityPolicyReferences(builder, role.Key, permission.ObjectKey, policy.Predicate, fmt.Sprintf("%s.policies[%d].predicate", path, policyIndex))
			}
		}
	}
	for _, binding := range snapshot.ProfileBindings {
		key := strings.TrimSpace(binding.ObjectKey)
		builder.Node("identity_profile_binding", key, binding.ObjectKey, binding.BusinessIdentity.Key, "")
		builder.Edge("identity_profile_binding", key, "object", binding.ObjectKey, "binds_profile_object", "object_key")
		builder.Edge("identity_profile_binding", key, "field", binding.ObjectKey+"."+binding.IdentityRelationField, "binds_identity_field", "identity_relation_field")
		for index, field := range binding.SummaryFields {
			builder.Edge("identity_profile_binding", key, "field", binding.ObjectKey+"."+field, "reads_summary_field", fmt.Sprintf("summary_fields[%d]", index))
		}
	}
}

func addIdentityPolicyReferences(builder *changeplanprojection.ChangePlanReferenceGraphBuilder, roleKey, objectKey string, expression *identitymodel.IdentityPolicyExpression, path string) {
	if expression == nil {
		return
	}
	currentObject := strings.TrimSpace(objectKey)
	for index, segment := range expression.Path {
		fieldObject := currentObject
		if strings.TrimSpace(segment.Direction) == "reverse" {
			fieldObject = strings.TrimSpace(segment.TargetObjectKey)
		}
		builder.Edge("role", roleKey, "field", fieldObject+"."+segment.RelationFieldKey, "traverses_policy_relation", fmt.Sprintf("%s.path[%d].relation_field_key", path, index))
		builder.Edge("role", roleKey, "object", segment.TargetObjectKey, "traverses_policy_object", fmt.Sprintf("%s.path[%d].target_object_key", path, index))
		currentObject = strings.TrimSpace(segment.TargetObjectKey)
	}
	if field := strings.TrimSpace(expression.FieldKey); currentObject != "" && field != "" {
		builder.Edge("role", roleKey, "field", currentObject+"."+field, "checks_policy_field", path+".field_key")
	}
	for index := range expression.Children {
		child := expression.Children[index]
		addIdentityPolicyReferences(builder, roleKey, objectKey, &child, fmt.Sprintf("%s.children[%d]", path, index))
	}
}

func AddActionReferences(builder *changeplanprojection.ChangePlanReferenceGraphBuilder, snapshot ReferenceSchema) {
	for _, action := range snapshot.Actions {
		builder.Node("action", action.Key, action.ObjectKey, action.Label, "")
		builder.Edge("action", action.Key, "object", action.ObjectKey, "operates_on", "object_key")
		builder.Edge("action", action.Key, "permission", action.RequiresPermission, "requires_permission", "requires_permission")
	}
}

func referenceRelationTarget(field definitionmodel.FieldSchema) string {
	for _, key := range []string{"object_key", "target", "target_object"} {
		value := strings.TrimSpace(fmt.Sprint(field.Config[key]))
		if value != "" && value != "<nil>" {
			return value
		}
	}
	return strings.TrimSpace(field.Validation.Target)
}
