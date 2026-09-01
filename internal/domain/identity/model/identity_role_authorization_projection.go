package identitymodel

import (
	"encoding/json"
	"sort"
	"strings"
)

// IdentityExpandRoleAuthorization projects reusable non-functional policy and
// deny guardrails into immutable effective Role schemas. RoleSchema.Permissions
// is copied only from the role itself and is never expanded by a permission set.
func IdentityExpandRoleAuthorization(roles []RoleSchema, sets []IdentityPermissionSet, groups []IdentityPermissionSetGroup, guardrails []IdentityGuardrailPolicy) []RoleSchema {
	setByKey := map[string]IdentityPermissionSet{}
	for _, set := range sets {
		if key := strings.TrimSpace(set.Key); key != "" {
			set.Key = key
			setByKey[key] = set
		}
	}
	groupByKey := map[string]IdentityPermissionSetGroup{}
	for _, group := range groups {
		if key := strings.TrimSpace(group.Key); key != "" {
			group.Key = key
			groupByKey[key] = group
		}
	}
	guardrailByKey := map[string]IdentityGuardrailPolicy{}
	for _, guardrail := range guardrails {
		if key := strings.TrimSpace(guardrail.Key); key != "" {
			guardrail.Key = key
			guardrailByKey[key] = guardrail
		}
	}
	out := make([]RoleSchema, len(roles))
	for index, role := range roles {
		role.DataPermissions = append([]DataPermission(nil), role.DataPermissions...)
		role.FieldPermissions = append([]FieldPermission(nil), role.FieldPermissions...)
		role.ReferencePermissions = append([]ReferencePermission(nil), role.ReferencePermissions...)
		role.ExportRules = append([]ExportRule(nil), role.ExportRules...)
		role.Guardrails = append([]IdentityGuardrailPolicy(nil), role.Guardrails...)
		setKeys := map[string]bool{}
		for _, key := range role.PermissionSetKeys {
			if key = strings.TrimSpace(key); key != "" {
				setKeys[key] = true
			}
		}
		for _, groupKey := range role.PermissionSetGroups {
			group, ok := groupByKey[strings.TrimSpace(groupKey)]
			if !ok {
				continue
			}
			for _, key := range group.PermissionSetKeys {
				if key = strings.TrimSpace(key); key != "" {
					setKeys[key] = true
				}
			}
		}
		ordered := make([]string, 0, len(setKeys))
		for key := range setKeys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			set, ok := setByKey[key]
			if !ok {
				continue
			}
			role.DataPermissions = append(role.DataPermissions, set.DataPermissions...)
			role.FieldPermissions = append(role.FieldPermissions, set.FieldPermissions...)
			role.ReferencePermissions = append(role.ReferencePermissions, set.ReferencePermissions...)
			role.ExportRules = append(role.ExportRules, set.ExportRules...)
		}
		for _, key := range identityUniqueSortedStrings(role.GuardrailKeys) {
			if guardrail, ok := guardrailByKey[key]; ok {
				role.Guardrails = append(role.Guardrails, guardrail)
			}
		}
		role.Permissions = identityUniqueSortedStrings(role.Permissions)
		identityCanonicalizeRoleAuthorization(&role)
		out[index] = role
	}
	return out
}

func identityUniqueSortedStrings(values []string) []string {
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

func identityCanonicalizeRoleAuthorization(role *RoleSchema) {
	canonical := func(value any) string {
		raw, _ := json.Marshal(value)
		return string(raw)
	}
	sort.Slice(role.DataPermissions, func(i, j int) bool { return canonical(role.DataPermissions[i]) < canonical(role.DataPermissions[j]) })
	sort.Slice(role.FieldPermissions, func(i, j int) bool { return canonical(role.FieldPermissions[i]) < canonical(role.FieldPermissions[j]) })
	sort.Slice(role.ReferencePermissions, func(i, j int) bool {
		return canonical(role.ReferencePermissions[i]) < canonical(role.ReferencePermissions[j])
	})
	sort.Slice(role.ExportRules, func(i, j int) bool { return canonical(role.ExportRules[i]) < canonical(role.ExportRules[j]) })
	sort.Slice(role.Guardrails, func(i, j int) bool { return canonical(role.Guardrails[i]) < canonical(role.Guardrails[j]) })
}
