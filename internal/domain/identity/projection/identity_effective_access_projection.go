package projection

import (
	"sort"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type IdentityEffectiveFieldDecision func(identitymodel.RoleSchema, definitionmodel.ObjectSchema, definitionmodel.FieldSchema) (bool, bool, bool, bool)

type IdentityEffectiveAccessProjectionInput struct {
	Principal           identitymodel.Principal
	Assignments         []identitymodel.IdentityUserRoleAssignment
	DirectoryRoles      []identitymodel.IdentityRole
	RoleDefinitions     []identitymodel.RoleSchema
	PermissionSets      []identitymodel.IdentityPermissionSet
	PermissionSetGroups []identitymodel.IdentityPermissionSetGroup
	Menus               []identitymodel.IdentityMenu
	RoleMenus           []identitymodel.IdentityRoleMenuAssignment
	Objects             []definitionmodel.ObjectSchema
	FieldDecision       IdentityEffectiveFieldDecision
}

func IdentityBuildEffectiveAccessSnapshot(input IdentityEffectiveAccessProjectionInput) identitymodel.IdentityEffectiveAccessSnapshot {
	snapshot := identitymodel.IdentityEffectiveAccessSnapshot{
		UserID: input.Principal.UserID, Known: input.Principal.Known, AuthorizationRevision: input.Principal.AuthorizationRevision,
		OrgID: input.Principal.OrgID, SupportOrgID: input.Principal.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), input.Principal.SupportOrgScopeIDs...), OrganizationPath: input.Principal.OrganizationPath,
		BusinessProfiles:     append([]identitymodel.BusinessProfileReference(nil), input.Principal.BusinessProfiles...),
		RoleAssignments:      append([]identitymodel.IdentityUserRoleAssignment(nil), input.Assignments...),
		ReferencePermissions: append([]identitymodel.ReferencePermission(nil), input.Principal.Role.ReferencePermissions...),
		ExportRules:          append([]identitymodel.ExportRule(nil), input.Principal.Role.ExportRules...),
	}
	roleByID := map[string]identitymodel.IdentityRole{}
	for _, role := range input.DirectoryRoles {
		roleByID[role.ID] = role
	}
	definitionByKey := map[string]identitymodel.RoleSchema{}
	for _, role := range input.RoleDefinitions {
		definitionByKey[strings.TrimSpace(role.Key)] = role
	}
	groupByKey := map[string]identitymodel.IdentityPermissionSetGroup{}
	for _, group := range input.PermissionSetGroups {
		groupByKey[strings.TrimSpace(group.Key)] = group
	}
	roleSources := map[string][]identitymodel.IdentityGrantSource{}
	for _, assignment := range snapshot.RoleAssignments {
		role := roleByID[assignment.RoleID]
		roleKey := strings.TrimSpace(role.Key)
		if roleKey == "" {
			roleKey = strings.TrimSpace(role.ID)
		}
		source := identitymodel.IdentityGrantSource{
			Type: "role_assignment", Key: assignment.RoleID, RoleID: assignment.RoleID, RoleKey: roleKey,
			AssignmentSource: assignment.Source, BindingKey: assignment.BindingKey, ProfileID: assignment.ProfileID,
			ValidFrom: assignment.ValidFrom, ValidUntil: assignment.ValidUntil,
		}
		if assignment.ExpiresAt != nil {
			source.ExpiresAt = *assignment.ExpiresAt
		}
		roleSources[roleKey] = append(roleSources[roleKey], source)
		snapshot.RoleKeys = append(snapshot.RoleKeys, roleKey)
		definition := definitionByKey[roleKey]
		for _, key := range definition.PermissionSetKeys {
			key = strings.TrimSpace(key)
			snapshot.PermissionSetKeys = append(snapshot.PermissionSetKeys, key)
			roleSources[roleKey] = append(roleSources[roleKey], identitymodel.IdentityGrantSource{Type: "permission_set", Key: key, RoleID: role.ID, RoleKey: roleKey, PermissionSetKey: key})
		}
		for _, groupKey := range definition.PermissionSetGroups {
			groupKey = strings.TrimSpace(groupKey)
			snapshot.PermissionSetGroups = append(snapshot.PermissionSetGroups, groupKey)
			for _, setKey := range groupByKey[groupKey].PermissionSetKeys {
				setKey = strings.TrimSpace(setKey)
				snapshot.PermissionSetKeys = append(snapshot.PermissionSetKeys, setKey)
				roleSources[roleKey] = append(roleSources[roleKey], identitymodel.IdentityGrantSource{Type: "permission_set_group", Key: groupKey, RoleID: role.ID, RoleKey: roleKey, PermissionSetKey: setKey, PermissionSetGroup: groupKey})
			}
		}
		snapshot.GuardrailKeys = append(snapshot.GuardrailKeys, definition.GuardrailKeys...)
	}
	snapshot.RoleKeys = identityProjectionUniqueStrings(snapshot.RoleKeys)
	snapshot.PermissionSetKeys = identityProjectionUniqueStrings(snapshot.PermissionSetKeys)
	snapshot.PermissionSetGroups = identityProjectionUniqueStrings(snapshot.PermissionSetGroups)
	snapshot.GuardrailKeys = identityProjectionUniqueStrings(snapshot.GuardrailKeys)
	sort.Slice(snapshot.RoleAssignments, func(left, right int) bool {
		return identityProjectionAssignmentKey(snapshot.RoleAssignments[left]) < identityProjectionAssignmentKey(snapshot.RoleAssignments[right])
	})
	for _, key := range input.Principal.Role.Permissions {
		objectKey, action := identityProjectionPermissionParts(key)
		sources := identityProjectionSourcesForGrant(key, roleSources, definitionByKey)
		snapshot.Permissions = append(snapshot.Permissions, identitymodel.IdentityEffectivePermissionGrant{Key: key, ObjectKey: objectKey, Action: action, Sources: sources})
	}
	snapshot.DataAccess = identityProjectionDataAccess(input.Principal.Role, roleSources)
	snapshot.FieldAccess = identityProjectionFieldAccess(input.Principal.Role, input.Objects, roleSources, input.FieldDecision)
	activeRoleIDs := map[string]bool{}
	for _, assignment := range snapshot.RoleAssignments {
		activeRoleIDs[assignment.RoleID] = true
	}
	menuIDs := map[string]bool{}
	for _, assignment := range input.RoleMenus {
		if activeRoleIDs[assignment.RoleID] {
			menuIDs[assignment.MenuID] = true
		}
	}
	for _, menu := range input.Menus {
		if menuIDs[menu.ID] && (menu.Status == "" || menu.Status == identitymodel.IdentityStatusActive) {
			snapshot.Menus = append(snapshot.Menus, menu)
		}
	}
	sort.Slice(snapshot.Menus, func(left, right int) bool { return snapshot.Menus[left].Key < snapshot.Menus[right].Key })
	return snapshot
}

func IdentityExplainEffectiveAccess(snapshot identitymodel.IdentityEffectiveAccessSnapshot, role identitymodel.RoleSchema, request identitymodel.IdentityAccessExplainRequest) identitymodel.IdentityAccessExplainResult {
	result := identitymodel.IdentityAccessExplainResult{
		UserID: request.UserID, ObjectKey: strings.TrimSpace(request.ObjectKey), Action: strings.TrimSpace(request.Action),
		FieldKey: strings.TrimSpace(request.FieldKey), RecordID: strings.TrimSpace(request.RecordID), AuthorizationRevision: snapshot.AuthorizationRevision,
	}
	if !snapshot.Known {
		result.Reason = identitymodel.IdentityAccessReason{Code: "identity_unknown", Effect: "deny", Layer: "identity"}
		return result
	}
	if result.ObjectKey == "" || result.Action == "" {
		result.Reason = identitymodel.IdentityAccessReason{Code: "object_and_action_required", Effect: "deny", Layer: "request"}
		return result
	}
	permissionKey := result.ObjectKey + "." + result.Action
	permission, permissionAllowed := identityProjectionPermissionForAction(snapshot.Permissions, result.ObjectKey, result.Action)
	if identitycontract.IdentityRoleGuardrailDeniesPermission(role, permissionKey) ||
		permissionAllowed && identitycontract.IdentityRoleGuardrailDeniesPermission(role, permission.Key) {
		result.Reason = identitymodel.IdentityAccessReason{Code: "guardrail_permission_denied", Effect: "deny", Layer: "guardrail", Subject: permissionKey}
		return result
	}
	if !permissionAllowed && !identitycontract.IdentityRoleAllows(role, result.ObjectKey, result.Action) {
		result.Reason = identitymodel.IdentityAccessReason{Code: "functional_permission_missing", Effect: "deny", Layer: "functional", Subject: permissionKey}
		return result
	}
	children := []identitymodel.IdentityAccessReason{{Code: "functional_permission_allowed", Effect: "allow", Layer: "functional", Subject: permissionKey, Sources: permission.Sources}}
	if identitycontract.IdentityRoleGuardrailDeniesData(role, result.ObjectKey, result.Action) {
		result.Reason = identitymodel.IdentityAccessReason{Code: "guardrail_data_denied", Effect: "deny", Layer: "guardrail", Subject: result.ObjectKey, Children: children}
		return result
	}
	data, dataAllowed := identityProjectionData(snapshot.DataAccess, result.ObjectKey, result.Action)
	if !dataAllowed {
		result.Reason = identitymodel.IdentityAccessReason{Code: "data_permission_missing", Effect: "deny", Layer: "data", Subject: result.ObjectKey, Children: children}
		return result
	}
	children = append(children, identitymodel.IdentityAccessReason{Code: "data_scope_allowed", Effect: "allow", Layer: "data", Subject: data.Scope, Sources: data.Sources})
	if result.FieldKey != "" {
		if identitycontract.IdentityRoleGuardrailDeniesField(role, result.ObjectKey, result.FieldKey, result.Action) {
			result.Reason = identitymodel.IdentityAccessReason{Code: "guardrail_field_denied", Effect: "deny", Layer: "guardrail", Subject: result.ObjectKey + "." + result.FieldKey, Children: children}
			return result
		}
		field, fieldAllowed := identityProjectionField(snapshot.FieldAccess, result.ObjectKey, result.FieldKey, result.Action)
		if !fieldAllowed {
			result.Reason = identitymodel.IdentityAccessReason{Code: "field_permission_denied", Effect: "deny", Layer: "field", Subject: result.ObjectKey + "." + result.FieldKey, Children: children}
			return result
		}
		children = append(children, identitymodel.IdentityAccessReason{Code: "field_permission_allowed", Effect: "allow", Layer: "field", Subject: result.ObjectKey + "." + result.FieldKey, Sources: field.Sources})
	}
	result.Allowed = true
	result.Reason = identitymodel.IdentityAccessReason{Code: "effective_access_allowed", Effect: "allow", Layer: "effective", Subject: permissionKey, Children: children}
	return result
}

func identityProjectionSourcesForGrant(key string, roleSources map[string][]identitymodel.IdentityGrantSource, roles map[string]identitymodel.RoleSchema) []identitymodel.IdentityGrantSource {
	out := []identitymodel.IdentityGrantSource{}
	for roleKey, sources := range roleSources {
		role := roles[roleKey]
		if !identityProjectionContains(role.Permissions, key) {
			continue
		}
		for _, source := range sources {
			if source.Type == "role_assignment" {
				out = append(out, source)
			}
		}
	}
	return identityProjectionUniqueSources(out)
}

func identityProjectionDataAccess(role identitymodel.RoleSchema, sources map[string][]identitymodel.IdentityGrantSource) []identitymodel.IdentityEffectiveDataAccess {
	type aggregate struct {
		scopes      []string
		predicates  []identitymodel.IdentityPolicyExpression
		auditDenial bool
		sources     []identitymodel.IdentityGrantSource
	}
	policiesByObject := map[string]*aggregate{}
	for _, permission := range role.DataPermissions {
		objectKey := strings.TrimSpace(permission.ObjectKey)
		if objectKey == "" {
			continue
		}
		if policiesByObject[objectKey] == nil {
			policiesByObject[objectKey] = &aggregate{}
		}
		value := policiesByObject[objectKey]
		value.scopes = append(value.scopes, permission.Scope)
		value.auditDenial = value.auditDenial || permission.AuditDenial
		if permission.Predicate != nil {
			value.predicates = append(value.predicates, *permission.Predicate)
		}
		for _, roleSources := range sources {
			value.sources = append(value.sources, roleSources...)
		}
	}
	effectiveObjects := map[string]bool{}
	for _, permissionKey := range role.Permissions {
		objectKey, action := identityProjectionPermissionParts(permissionKey)
		if objectKey == "" || action == "" || policiesByObject[objectKey] == nil {
			continue
		}
		effectiveObjects[objectKey] = true
	}
	out := make([]identitymodel.IdentityEffectiveDataAccess, 0, len(effectiveObjects))
	for objectKey := range effectiveObjects {
		value := policiesByObject[objectKey]
		scopes := identityProjectionUniqueStrings(value.scopes)
		scope := identityProjectionCombinedScope(scopes)
		var predicate *identitymodel.IdentityPolicyExpression
		if len(value.predicates) == 1 {
			value := value.predicates[0]
			predicate = &value
		} else if len(value.predicates) > 1 {
			predicate = &identitymodel.IdentityPolicyExpression{Operator: "or", Children: value.predicates}
		}
		out = append(out, identitymodel.IdentityEffectiveDataAccess{ObjectKey: objectKey, Allowed: true, Scope: scope, Scopes: scopes, Predicate: predicate, AuditDenial: value.auditDenial, Sources: identityProjectionUniqueSources(value.sources)})
	}
	sort.Slice(out, func(left, right int) bool {
		return out[left].ObjectKey < out[right].ObjectKey
	})
	return out
}

func identityProjectionFieldAccess(role identitymodel.RoleSchema, objects []definitionmodel.ObjectSchema, sources map[string][]identitymodel.IdentityGrantSource, decision IdentityEffectiveFieldDecision) []identitymodel.IdentityEffectiveFieldAccess {
	out := []identitymodel.IdentityEffectiveFieldAccess{}
	if decision == nil {
		return out
	}
	for _, object := range objects {
		for _, field := range object.Fields {
			if field.DisabledAt != "" {
				continue
			}
			fieldSources := []identitymodel.IdentityGrantSource{}
			for _, roleSources := range sources {
				fieldSources = append(fieldSources, roleSources...)
			}
			read, write, export, masked := decision(role, object, field)
			reason, rules := identityProjectionContextualFieldRules(role, object.Key, field.Key)
			out = append(out, identitymodel.IdentityEffectiveFieldAccess{
				ObjectKey: object.Key, FieldKey: field.Key,
				Read: read, Write: write, Export: export, Masked: masked, Reason: reason, Policies: rules,
				Sensitive: identityProjectionSensitiveField(object, field), Sources: identityProjectionUniqueSources(fieldSources),
			})
		}
	}
	sort.Slice(out, func(left, right int) bool {
		return out[left].ObjectKey+"\x00"+out[left].FieldKey < out[right].ObjectKey+"\x00"+out[right].FieldKey
	})
	return out
}

func identityProjectionContextualFieldRules(role identitymodel.RoleSchema, objectKey, fieldKey string) (string, []identitymodel.ContextualFieldPolicyRule) {
	reason := ""
	rules := []identitymodel.ContextualFieldPolicyRule{}
	for _, permission := range role.FieldPermissions {
		if permission.ObjectKey != objectKey || permission.FieldKey != fieldKey && permission.FieldKey != "*" {
			continue
		}
		if reason == "" {
			reason = permission.Reason
		}
		rules = append(rules, cloneIdentityProjectionFieldRules(permission.Policies)...)
	}
	return reason, rules
}

func cloneIdentityProjectionFieldRules(values []identitymodel.ContextualFieldPolicyRule) []identitymodel.ContextualFieldPolicyRule {
	result := make([]identitymodel.ContextualFieldPolicyRule, len(values))
	for index := range values {
		result[index] = values[index]
		result[index].Actions = append([]string(nil), values[index].Actions...)
		if values[index].Predicate != nil {
			predicate := cloneIdentityProjectionPredicate(*values[index].Predicate)
			result[index].Predicate = &predicate
		}
		if values[index].MaskStrategy != nil {
			strategy := *values[index].MaskStrategy
			result[index].MaskStrategy = &strategy
		}
	}
	return result
}

func cloneIdentityProjectionPredicate(value identitymodel.IdentityPolicyExpression) identitymodel.IdentityPolicyExpression {
	value.Path = append([]identitymodel.IdentityPolicyRelationSegment(nil), value.Path...)
	value.Values = append([]string(nil), value.Values...)
	value.Children = append([]identitymodel.IdentityPolicyExpression(nil), value.Children...)
	for index := range value.Children {
		value.Children[index] = cloneIdentityProjectionPredicate(value.Children[index])
	}
	return value
}

func identityProjectionPermission(values []identitymodel.IdentityEffectivePermissionGrant, key string) (identitymodel.IdentityEffectivePermissionGrant, bool) {
	for _, value := range values {
		if value.Key == key {
			return value, true
		}
	}
	return identitymodel.IdentityEffectivePermissionGrant{}, false
}

func identityProjectionPermissionForAction(values []identitymodel.IdentityEffectivePermissionGrant, objectKey, action string) (identitymodel.IdentityEffectivePermissionGrant, bool) {
	for _, value := range values {
		if value.ObjectKey == objectKey && value.Action == action {
			return value, true
		}
	}
	return identityProjectionPermission(values, objectKey+"."+action)
}

func identityProjectionData(values []identitymodel.IdentityEffectiveDataAccess, objectKey, _ string) (identitymodel.IdentityEffectiveDataAccess, bool) {
	for _, value := range values {
		if value.ObjectKey == objectKey && value.Allowed {
			return value, true
		}
	}
	return identitymodel.IdentityEffectiveDataAccess{}, false
}

func identityProjectionField(values []identitymodel.IdentityEffectiveFieldAccess, objectKey, fieldKey, action string) (identitymodel.IdentityEffectiveFieldAccess, bool) {
	for _, value := range values {
		if value.ObjectKey != objectKey || value.FieldKey != fieldKey {
			continue
		}
		switch action {
		case "export":
			return value, value.Export
		case "update", "write", "create":
			return value, value.Write
		default:
			return value, value.Read
		}
	}
	return identitymodel.IdentityEffectiveFieldAccess{}, false
}

func identityProjectionPermissionParts(key string) (string, string) {
	parts := strings.Split(strings.TrimSpace(key), ".")
	if len(parts) < 2 {
		return "", strings.TrimSpace(key)
	}
	return strings.Join(parts[:len(parts)-1], "."), parts[len(parts)-1]
}

func identityProjectionAssignmentKey(value identitymodel.IdentityUserRoleAssignment) string {
	return value.UserID + "\x00" + value.RoleID + "\x00" + value.BindingKey + "\x00" + value.ProfileID
}

func identityProjectionCombinedScope(scopes []string) string {
	for _, scope := range scopes {
		if scope == "all_records" {
			return "all_records"
		}
	}
	if len(scopes) == 0 {
		return "none"
	}
	if len(scopes) == 1 {
		return scopes[0]
	}
	return "union"
}

func identityProjectionContains(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func identityProjectionUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func identityProjectionUniqueSources(values []identitymodel.IdentityGrantSource) []identitymodel.IdentityGrantSource {
	seen := map[string]bool{}
	out := []identitymodel.IdentityGrantSource{}
	for _, value := range values {
		key := value.Type + "\x00" + value.Key + "\x00" + value.RoleID + "\x00" + value.PermissionSetKey + "\x00" + value.PermissionSetGroup
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	sort.Slice(out, func(left, right int) bool {
		return out[left].Type+"\x00"+out[left].Key+"\x00"+out[left].RoleID < out[right].Type+"\x00"+out[right].Key+"\x00"+out[right].RoleID
	})
	return out
}

func identityProjectionSensitiveField(object definitionmodel.ObjectSchema, field definitionmodel.FieldSchema) bool {
	if strings.TrimSpace(identityProjectionString(object.Config["field_access_mode"])) == "default_deny" {
		return true
	}
	if sensitive, ok := field.Config["sensitive"].(bool); ok && sensitive {
		return true
	}
	switch strings.TrimSpace(identityProjectionString(field.Config["sensitivity"])) {
	case "sensitive", "secret", "credential", "security_raw", "key_material":
		return true
	default:
		return false
	}
}

func identityProjectionString(value any) string {
	text, _ := value.(string)
	return text
}
