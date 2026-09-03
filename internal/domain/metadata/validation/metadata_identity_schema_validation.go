package validation

import (
	"fmt"
	"sort"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
)

// MetadataValidateIdentitySchema validates only the metadata graph owned by
// Identity: business object shape, relation references and authorization
// references. It deliberately knows nothing about workflow, automation,
// reporting, agents or integrations.
func MetadataValidateIdentitySchema(schema manifestmodel.ManifestSchema) error {
	validator := newIdentitySchemaValidator(schema)
	validator.validateObjects()
	validator.validateViewsAndActions()
	validator.validateAuthorization()
	validator.validateProfileBindings()
	if len(validator.issues) == 0 {
		return nil
	}
	sort.Strings(validator.issues)
	return fmt.Errorf("%s", strings.Join(validator.issues, "; "))
}

type identitySchemaValidator struct {
	schema  manifestmodel.ManifestSchema
	objects map[string]definitionmodel.ObjectSchema
	fields  map[string]map[string]definitionmodel.FieldSchema
	actions map[string]definitionmodel.ActionSchema
	roles   map[string]identitymodel.RoleSchema
	issues  []string
}

func newIdentitySchemaValidator(schema manifestmodel.ManifestSchema) *identitySchemaValidator {
	validator := &identitySchemaValidator{
		schema:  schema,
		objects: map[string]definitionmodel.ObjectSchema{},
		fields:  map[string]map[string]definitionmodel.FieldSchema{},
		actions: map[string]definitionmodel.ActionSchema{},
		roles:   map[string]identitymodel.RoleSchema{},
	}
	for _, object := range schema.Objects {
		key := strings.TrimSpace(object.Key)
		if key == "" {
			continue
		}
		validator.objects[key] = object
		validator.fields[key] = map[string]definitionmodel.FieldSchema{}
		for _, field := range object.Fields {
			if fieldKey := strings.TrimSpace(field.Key); fieldKey != "" {
				validator.fields[key][fieldKey] = field
			}
		}
	}
	for _, action := range schema.Actions {
		if key := strings.TrimSpace(action.Key); key != "" {
			validator.actions[key] = action
		}
	}
	for _, role := range schema.Roles {
		if key := strings.TrimSpace(role.Key); key != "" {
			validator.roles[key] = role
		}
	}
	return validator
}

func (validator *identitySchemaValidator) add(path, format string, args ...any) {
	validator.issues = append(validator.issues, path+": "+fmt.Sprintf(format, args...))
}

func (validator *identitySchemaValidator) validateObjects() {
	seenObjects := map[string]bool{}
	for objectIndex, object := range validator.schema.Objects {
		path := fmt.Sprintf("objects[%d]", objectIndex)
		objectKey := strings.TrimSpace(object.Key)
		if objectKey == "" {
			validator.add(path+".key", "is required")
			continue
		}
		if seenObjects[objectKey] {
			validator.add(path+".key", "duplicate object %q", objectKey)
		}
		seenObjects[objectKey] = true
		seenFields := map[string]bool{}
		for fieldIndex, field := range object.Fields {
			fieldPath := fmt.Sprintf("%s.fields[%d]", path, fieldIndex)
			fieldKey := strings.TrimSpace(field.Key)
			if fieldKey == "" {
				validator.add(fieldPath+".key", "is required")
				continue
			}
			if seenFields[fieldKey] {
				validator.add(fieldPath+".key", "duplicate field %q", fieldKey)
			}
			seenFields[fieldKey] = true
			if strings.TrimSpace(field.Type) == "" {
				validator.add(fieldPath+".type", "is required")
			}
			if strings.TrimSpace(field.Type) == "relation" {
				target := identityRelationTarget(field)
				if target == "" {
					validator.add(fieldPath+".validation.target", "is required for relation fields")
				} else if _, exists := validator.objects[target]; !exists && !identitycontract.IsFoundationObjectKey(target) {
					validator.add(fieldPath+".validation.target", "references unknown object %q", target)
				}
			}
		}
		seenValidations := map[string]bool{}
		for validationIndex, validation := range object.Validations {
			validationPath := fmt.Sprintf("%s.validations[%d]", path, validationIndex)
			key := strings.TrimSpace(validation.Key)
			if key == "" {
				validator.add(validationPath+".key", "is required")
			} else if seenValidations[key] {
				validator.add(validationPath+".key", "duplicate validation %q", key)
			}
			seenValidations[key] = true
			if owner := strings.TrimSpace(validation.ObjectKey); owner != objectKey {
				validator.add(validationPath+".object_key", "must be %q", objectKey)
			}
			if fieldKey := strings.TrimSpace(validation.FieldKey); fieldKey != "" && validator.fields[objectKey][fieldKey].Key == "" {
				validator.add(validationPath+".field_key", "references unknown field %q", fieldKey)
			}
			for _, fieldKey := range validation.Fields {
				if validator.fields[objectKey][strings.TrimSpace(fieldKey)].Key == "" {
					validator.add(validationPath+".fields", "references unknown field %q", fieldKey)
				}
			}
		}
	}
}

func (validator *identitySchemaValidator) validateViewsAndActions() {
	seenActions := map[string]bool{}
	for index, action := range validator.schema.Actions {
		path := fmt.Sprintf("actions[%d]", index)
		key := strings.TrimSpace(action.Key)
		if key == "" {
			validator.add(path+".key", "is required")
		} else if seenActions[key] {
			validator.add(path+".key", "duplicate action %q", key)
		}
		seenActions[key] = true
		if _, exists := validator.objects[strings.TrimSpace(action.ObjectKey)]; !exists {
			validator.add(path+".object_key", "references unknown object %q", action.ObjectKey)
		}
	}
}

func (validator *identitySchemaValidator) validateAuthorization() {
	seenRoles := map[string]bool{}
	for roleIndex, role := range validator.schema.Roles {
		path := fmt.Sprintf("roles[%d]", roleIndex)
		roleKey := strings.TrimSpace(role.Key)
		if roleKey == "" {
			validator.add(path+".key", "is required")
		} else if seenRoles[roleKey] {
			validator.add(path+".key", "duplicate role %q", roleKey)
		}
		seenRoles[roleKey] = true
		for _, conflictRoleKey := range role.ConflictRoleKeys {
			key := strings.TrimSpace(conflictRoleKey)
			if key == roleKey {
				validator.add(path+".conflict_role_keys", "must not reference itself")
			} else if _, exists := validator.roles[key]; !exists {
				validator.add(path+".conflict_role_keys", "references unknown role %q", key)
			}
		}
		for index, permission := range role.Permissions {
			permissionPath := fmt.Sprintf("%s.permissions[%d]", path, index)
			if strings.TrimSpace(permission.PermissionKey) == "" {
				validator.add(permissionPath+".permission_key", "is required")
			}
			if _, ok := identitymodel.CanonicalIdentityDataScope(strings.TrimSpace(string(permission.DataScope))); !ok {
				validator.add(permissionPath+".data_scope", "unsupported scope %q", permission.DataScope)
			}
		}
		for index, permission := range role.FieldPermissions {
			permissionPath := fmt.Sprintf("%s.field_permissions[%d]", path, index)
			objectKey, fieldKey := strings.TrimSpace(permission.ObjectKey), strings.TrimSpace(permission.FieldKey)
			if objectKey == "" {
				validator.add(permissionPath+".object_key", "is required")
			}
			if fieldKey == "" {
				validator.add(permissionPath+".field_key", "is required")
			} else if _, localObject := validator.objects[objectKey]; localObject && fieldKey != "*" && validator.fields[objectKey][fieldKey].Key == "" {
				validator.add(permissionPath+".field_key", "references unknown field %s.%s", permission.ObjectKey, permission.FieldKey)
			}
		}
		for index, permission := range role.ReferencePermissions {
			validator.validateReferencePermission(fmt.Sprintf("%s.reference_permissions[%d]", path, index), permission)
		}
		for index, rule := range role.ExportRules {
			rulePath := fmt.Sprintf("%s.export_rules[%d]", path, index)
			objectKey := strings.TrimSpace(rule.ObjectKey)
			if objectKey == "" {
				validator.add(rulePath+".object_key", "is required")
			}
			for fieldIndex, rawFieldKey := range rule.Fields {
				fieldKey := strings.TrimSpace(rawFieldKey)
				if fieldKey == "" {
					validator.add(fmt.Sprintf("%s.fields[%d]", rulePath, fieldIndex), "is required")
				} else if _, localObject := validator.objects[objectKey]; localObject && fieldKey != "id" && validator.fields[objectKey][fieldKey].Key == "" {
					validator.add(rulePath+".fields", "references unknown field %s.%s", objectKey, fieldKey)
				}
			}
		}
	}
}

func (validator *identitySchemaValidator) validateReferencePermission(path string, permission identitymodel.ReferencePermission) {
	sourceKey := strings.TrimSpace(permission.SourceObjectKey)
	targetKey := strings.TrimSpace(permission.TargetObjectKey)
	relationKey := strings.TrimSpace(permission.RelationFieldKey)
	if sourceKey == "" {
		validator.add(path+".source_object_key", "is required")
	}
	if targetKey == "" {
		validator.add(path+".target_object_key", "is required")
	}
	if relationKey == "" {
		validator.add(path+".relation_field_key", "is required")
	}
	field := validator.fields[sourceKey][relationKey]
	if _, localSource := validator.objects[sourceKey]; localSource && field.Key == "" {
		validator.add(path+".relation_field_key", "references unknown field %q", permission.RelationFieldKey)
	} else if strings.TrimSpace(field.Type) != "relation" {
		if field.Key != "" {
			validator.add(path+".relation_field_key", "must reference a relation field")
		}
	} else if relationTarget := identityRelationTarget(field); relationTarget != "" && relationTarget != targetKey {
		validator.add(path+".target_object_key", "must match relation target %q", relationTarget)
	}
	for index, rawFieldKey := range permission.DisplayFields {
		fieldKey := strings.TrimSpace(rawFieldKey)
		if fieldKey == "" {
			validator.add(fmt.Sprintf("%s.display_fields[%d]", path, index), "is required")
		} else if _, localTarget := validator.objects[targetKey]; localTarget && fieldKey != "id" && validator.fields[targetKey][fieldKey].Key == "" {
			validator.add(path+".display_fields", "references unknown field %s.%s", targetKey, fieldKey)
		}
	}
}

func (validator *identitySchemaValidator) validatePolicyExpression(path string, expression identitymodel.IdentityPolicyExpression, depth int) {
	if depth > 16 {
		validator.add(path, "exceeds maximum depth")
		return
	}
	operator := strings.ToLower(strings.TrimSpace(expression.Operator))
	if operator == "" {
		validator.add(path+".operator", "is required")
		return
	}
	switch operator {
	case "and", "or":
		if len(expression.Children) == 0 {
			validator.add(path+".children", "must not be empty for %s", operator)
		}
		for index, child := range expression.Children {
			validator.validatePolicyExpression(fmt.Sprintf("%s.children[%d]", path, index), child, depth+1)
		}
		return
	case "not":
		if len(expression.Children) != 1 {
			validator.add(path+".children", "must contain exactly one expression for not")
		}
		for index, child := range expression.Children {
			validator.validatePolicyExpression(fmt.Sprintf("%s.children[%d]", path, index), child, depth+1)
		}
		return
	}
	if len(expression.Path) > 3 {
		validator.add(path+".path", "must contain at most 3 relation segments")
	}
	for index, segment := range expression.Path {
		segmentPath := fmt.Sprintf("%s.path[%d]", path, index)
		if direction := strings.TrimSpace(segment.Direction); direction != "forward" && direction != "reverse" {
			validator.add(segmentPath+".direction", "must be forward or reverse")
		}
		if strings.TrimSpace(segment.RelationFieldKey) == "" {
			validator.add(segmentPath+".relation_field_key", "is required")
		}
		if strings.TrimSpace(segment.TargetObjectKey) == "" {
			validator.add(segmentPath+".target_object_key", "is required")
		}
	}
	if strings.TrimSpace(expression.FieldKey) == "" {
		validator.add(path+".field_key", "is required")
	}
	valueSource := strings.TrimSpace(expression.ValueSource)
	if valueSource != "literal" && valueSource != "actor_claim" {
		validator.add(path+".value_source", "must be literal or actor_claim")
	} else if valueSource == "actor_claim" && strings.TrimSpace(expression.ClaimKey) == "" {
		validator.add(path+".claim_key", "is required for actor_claim")
	}
}

func (validator *identitySchemaValidator) validateProfileBindings() {
	seenObjects, seenBindings := map[string]bool{}, map[string]bool{}
	for index, binding := range validator.schema.IdentityProfileExtensions {
		path := fmt.Sprintf("identity_profile_extensions[%d]", index)
		objectKey := strings.TrimSpace(binding.ObjectKey)
		if binding.ContractVersion != identitymodel.IdentityProfileExtensionContractVersion {
			validator.add(path+".contract_version", "must be %q", identitymodel.IdentityProfileExtensionContractVersion)
		}
		if binding.MinReaderVersion != identitymodel.IdentityProfileExtensionMinReaderVersion {
			validator.add(path+".min_reader_version", "must be %q", identitymodel.IdentityProfileExtensionMinReaderVersion)
		}
		if validator.objects[objectKey].Key == "" {
			validator.add(path+".object_key", "references unknown object %q", objectKey)
		} else if seenObjects[objectKey] {
			validator.add(path+".object_key", "duplicate profile binding for %q", objectKey)
		}
		seenObjects[objectKey] = true
		relationField := validator.fields[objectKey][strings.TrimSpace(binding.IdentityRelationField)]
		if relationField.Key == "" || relationField.Type != "relation" || identityRelationTarget(relationField) != "identity_user" || !relationField.Unique {
			validator.add(path+".identity_relation_field", "must reference a unique relation targeting identity_user")
		}
		if binding.Cardinality != "one_to_one" {
			validator.add(path+".cardinality", "must be one_to_one")
		}
		bindingKey := strings.TrimSpace(binding.BusinessIdentity.Key)
		if bindingKey == "" {
			validator.add(path+".business_identity.key", "is required")
		} else if seenBindings[bindingKey] {
			validator.add(path+".business_identity.key", "duplicate binding %q", bindingKey)
		}
		seenBindings[bindingKey] = true
		if len(binding.BusinessIdentity.SurfaceKeys) == 0 {
			validator.add(path+".business_identity.surface_keys", "must not be empty")
		}
		validator.validateProfileFieldReferences(path, binding)
		if binding.DefaultVisibility != "when_readable" && binding.DefaultVisibility != "hidden" {
			validator.add(path+".default_visibility", "must be when_readable or hidden")
		}
	}
}

func (validator *identitySchemaValidator) validateProfileFieldReferences(path string, binding identitymodel.IdentityProfileExtension) {
	objectKey := strings.TrimSpace(binding.ObjectKey)
	fieldLists := [][]string{binding.SummaryFields, binding.Directory.SummaryFields, binding.Directory.FilterFields}
	for _, fields := range binding.ProfileTabFields {
		fieldLists = append(fieldLists, fields)
	}
	for _, fields := range fieldLists {
		for _, fieldKey := range fields {
			if validator.fields[objectKey][strings.TrimSpace(fieldKey)].Key == "" {
				validator.add(path, "references unknown profile field %q", fieldKey)
			}
		}
	}
	for _, claim := range binding.BusinessIdentity.Claims {
		if validator.fields[objectKey][strings.TrimSpace(claim.FieldKey)].Key == "" {
			validator.add(path+".business_identity.claims", "references unknown field %q", claim.FieldKey)
		}
	}
	for _, proof := range binding.BindingLifecycle.ClaimProofs {
		if validator.fields[objectKey][strings.TrimSpace(proof.FieldKey)].Key == "" {
			validator.add(path+".binding_lifecycle.claim_proofs", "references unknown field %q", proof.FieldKey)
		}
	}
}

func identityRelationTarget(field definitionmodel.FieldSchema) string {
	for _, key := range []string{"object_key", "target", "target_object"} {
		if value := strings.TrimSpace(fmt.Sprint(field.Config[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return strings.TrimSpace(field.Validation.Target)
}
