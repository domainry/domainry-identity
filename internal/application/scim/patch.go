package scim

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

var memberValuePath = regexp.MustCompile(`(?i)^members\s*\[\s*value\s+eq\s+"([^"]+)"\s*\]$`)
var multiValuePath = regexp.MustCompile(`(?i)^(emails|phoneNumbers)\s*\[\s*(type|value)\s+eq\s+"([^"]+)"\s*\](?:\.value)?$`)

func ApplyUserPatch(existing scimmodel.User, patch scimmodel.PatchRequest) (scimmodel.User, error) {
	if err := validatePatchRequest(patch); err != nil {
		return scimmodel.User{}, err
	}
	result := cloneUser(existing)
	for _, operation := range patch.Operations {
		op := strings.ToLower(strings.TrimSpace(operation.Op))
		if op != "add" && op != "replace" && op != "remove" {
			return scimmodel.User{}, invalidValue("PATCH op must be add, replace, or remove")
		}
		path := strings.TrimSpace(operation.Path)
		if path == "" {
			if op == "remove" {
				return scimmodel.User{}, invalidPath("remove requires a path")
			}
			object, ok := operation.Value.(map[string]any)
			if !ok {
				return scimmodel.User{}, invalidValue("pathless PATCH value must be an object")
			}
			for key, value := range object {
				if err := applyUserAttribute(&result, op, key, value); err != nil {
					return scimmodel.User{}, err
				}
			}
			continue
		}
		if err := applyUserAttribute(&result, op, path, operation.Value); err != nil {
			return scimmodel.User{}, err
		}
	}
	return result, nil
}

func applyUserAttribute(user *scimmodel.User, op, rawPath string, value any) error {
	path := strings.ToLower(strings.TrimSpace(rawPath))
	switch path {
	case "username":
		if op == "remove" {
			return invalidValue("userName cannot be removed")
		}
		user.UserName = stringValue(value)
	case "externalid":
		user.ExternalID = removedOrString(op, value)
	case "displayname":
		user.DisplayName = removedOrString(op, value)
	case "active":
		if op == "remove" {
			user.Active = nil
			return nil
		}
		active, ok := value.(bool)
		if !ok {
			return invalidValue("active must be a boolean")
		}
		user.Active = &active
	case "preferredlanguage":
		user.PreferredLang = removedOrString(op, value)
	case "locale":
		user.Locale = removedOrString(op, value)
	case "timezone":
		user.Timezone = removedOrString(op, value)
	case "name":
		if op == "remove" {
			user.Name = scimmodel.Name{}
			return nil
		}
		return decodeValue(value, &user.Name, "name")
	case "name.formatted":
		user.Name.Formatted = removedOrString(op, value)
	case "name.givenname":
		user.Name.GivenName = removedOrString(op, value)
	case "name.familyname":
		user.Name.FamilyName = removedOrString(op, value)
	case "name.middlename":
		user.Name.MiddleName = removedOrString(op, value)
	case "name.honorificprefix":
		user.Name.HonorificPrefix = removedOrString(op, value)
	case "name.honorificsuffix":
		user.Name.HonorificSuffix = removedOrString(op, value)
	case "emails":
		return applyMultiValues(&user.Emails, op, value, "emails")
	case "phonenumbers":
		return applyMultiValues(&user.PhoneNumbers, op, value, "phoneNumbers")
	case "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user":
		if op == "remove" {
			user.EnterpriseUser = nil
			return nil
		}
		var enterprise scimmodel.EnterpriseUser
		if err := decodeValue(value, &enterprise, "enterprise user extension"); err != nil {
			return err
		}
		user.EnterpriseUser = &enterprise
	case "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:employeenumber":
		ensureEnterprise(user)
		user.EnterpriseUser.EmployeeNumber = removedOrString(op, value)
	case "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:department":
		ensureEnterprise(user)
		user.EnterpriseUser.Department = removedOrString(op, value)
	case "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:manager.value":
		ensureEnterprise(user)
		if op == "remove" {
			user.EnterpriseUser.Manager = nil
		} else {
			if user.EnterpriseUser.Manager == nil {
				user.EnterpriseUser.Manager = &scimmodel.Manager{}
			}
			user.EnterpriseUser.Manager.Value = stringValue(value)
		}
	default:
		if match := multiValuePath.FindStringSubmatch(strings.TrimSpace(rawPath)); len(match) == 4 {
			values := &user.Emails
			if strings.EqualFold(match[1], "phoneNumbers") {
				values = &user.PhoneNumbers
			}
			return applySelectedMultiValue(values, op, match[2], match[3], value)
		}
		return invalidPath("unsupported User PATCH path: " + rawPath)
	}
	return nil
}

func ApplyGroupPatch(existing scimmodel.Group, patch scimmodel.PatchRequest) (scimmodel.Group, error) {
	if err := validatePatchRequest(patch); err != nil {
		return scimmodel.Group{}, err
	}
	result := existing
	result.Schemas = append([]string(nil), existing.Schemas...)
	result.Members = append([]scimmodel.Member(nil), existing.Members...)
	for _, operation := range patch.Operations {
		op := strings.ToLower(strings.TrimSpace(operation.Op))
		if op != "add" && op != "replace" && op != "remove" {
			return scimmodel.Group{}, invalidValue("PATCH op must be add, replace, or remove")
		}
		path := strings.TrimSpace(operation.Path)
		if path == "" {
			if op == "remove" {
				return scimmodel.Group{}, invalidPath("remove requires a path")
			}
			object, ok := operation.Value.(map[string]any)
			if !ok {
				return scimmodel.Group{}, invalidValue("pathless PATCH value must be an object")
			}
			for key, value := range object {
				if err := applyGroupAttribute(&result, op, key, value); err != nil {
					return scimmodel.Group{}, err
				}
			}
			continue
		}
		if err := applyGroupAttribute(&result, op, path, operation.Value); err != nil {
			return scimmodel.Group{}, err
		}
	}
	return result, nil
}

func applyGroupAttribute(group *scimmodel.Group, op, rawPath string, value any) error {
	path := strings.ToLower(strings.TrimSpace(rawPath))
	switch path {
	case "displayname":
		if op == "remove" {
			return invalidValue("displayName cannot be removed")
		}
		group.DisplayName = stringValue(value)
	case "externalid":
		group.ExternalID = removedOrString(op, value)
	case "members":
		if op == "remove" && value == nil {
			group.Members = nil
			return nil
		}
		members, err := memberValues(value)
		if err != nil {
			return err
		}
		switch op {
		case "add":
			group.Members = mergeMembers(group.Members, members)
		case "replace":
			group.Members = members
		case "remove":
			remove := map[string]struct{}{}
			for _, member := range members {
				remove[member.Value] = struct{}{}
			}
			filtered := group.Members[:0]
			for _, member := range group.Members {
				if _, found := remove[member.Value]; !found {
					filtered = append(filtered, member)
				}
			}
			group.Members = filtered
		}
	default:
		match := memberValuePath.FindStringSubmatch(strings.TrimSpace(rawPath))
		if len(match) != 2 || op != "remove" {
			return invalidPath("unsupported Group PATCH path: " + rawPath)
		}
		filtered := group.Members[:0]
		matched := false
		for _, member := range group.Members {
			if member.Value == match[1] {
				matched = true
				continue
			}
			filtered = append(filtered, member)
		}
		if !matched {
			return noTarget("Group PATCH path matched no member")
		}
		group.Members = filtered
	}
	return nil
}

func validatePatchRequest(patch scimmodel.PatchRequest) error {
	foundSchema := false
	for _, schema := range patch.Schemas {
		if schema == scimmodel.SchemaPatch {
			foundSchema = true
			break
		}
	}
	if !foundSchema {
		return invalidValue("PATCH request schemas must include PatchOp")
	}
	if len(patch.Operations) == 0 {
		return invalidValue("PATCH request must contain at least one operation")
	}
	return nil
}

func cloneUser(source scimmodel.User) scimmodel.User {
	result := source
	result.Schemas = append([]string(nil), source.Schemas...)
	result.Emails = append([]scimmodel.MultiValue(nil), source.Emails...)
	result.PhoneNumbers = append([]scimmodel.MultiValue(nil), source.PhoneNumbers...)
	if source.Active != nil {
		active := *source.Active
		result.Active = &active
	}
	if source.EnterpriseUser != nil {
		enterprise := *source.EnterpriseUser
		if source.EnterpriseUser.Manager != nil {
			manager := *source.EnterpriseUser.Manager
			enterprise.Manager = &manager
		}
		result.EnterpriseUser = &enterprise
	}
	return result
}

func applyMultiValues(target *[]scimmodel.MultiValue, op string, value any, label string) error {
	if op == "remove" {
		*target = nil
		return nil
	}
	var values []scimmodel.MultiValue
	if err := decodeValue(value, &values, label); err != nil {
		var single scimmodel.MultiValue
		if singleErr := decodeValue(value, &single, label); singleErr != nil {
			return err
		}
		values = []scimmodel.MultiValue{single}
	}
	if op == "add" {
		*target = mergeMultiValues(*target, values)
	} else {
		*target = values
	}
	return nil
}

func mergeMultiValues(existing, additions []scimmodel.MultiValue) []scimmodel.MultiValue {
	result := append([]scimmodel.MultiValue(nil), existing...)
	for _, addition := range additions {
		duplicate := false
		for _, current := range result {
			if strings.EqualFold(strings.TrimSpace(current.Value), strings.TrimSpace(addition.Value)) && strings.EqualFold(strings.TrimSpace(current.Type), strings.TrimSpace(addition.Type)) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, addition)
		}
	}
	return result
}

func applySelectedMultiValue(target *[]scimmodel.MultiValue, op, selector, expected string, value any) error {
	matched := false
	for index := range *target {
		actual := (*target)[index].Value
		if strings.EqualFold(selector, "type") {
			actual = (*target)[index].Type
		}
		if !strings.EqualFold(actual, expected) {
			continue
		}
		matched = true
		if op == "remove" {
			(*target)[index].Value = ""
		} else {
			(*target)[index].Value = stringValue(value)
		}
	}
	if !matched {
		return noTarget("PATCH path matched no multi-valued attribute")
	}
	if op == "remove" {
		filtered := (*target)[:0]
		for _, item := range *target {
			if item.Value != "" {
				filtered = append(filtered, item)
			}
		}
		*target = filtered
	}
	return nil
}

func memberValues(value any) ([]scimmodel.Member, error) {
	var members []scimmodel.Member
	if err := decodeValue(value, &members, "members"); err != nil {
		var member scimmodel.Member
		if singleErr := decodeValue(value, &member, "members"); singleErr != nil {
			return nil, err
		}
		members = []scimmodel.Member{member}
	}
	for index := range members {
		members[index].Value = strings.TrimSpace(members[index].Value)
		if members[index].Value == "" {
			return nil, invalidValue("group member value is required")
		}
	}
	return members, nil
}

func mergeMembers(existing, additions []scimmodel.Member) []scimmodel.Member {
	result := append([]scimmodel.Member(nil), existing...)
	seen := map[string]struct{}{}
	for _, member := range result {
		seen[member.Value] = struct{}{}
	}
	for _, member := range additions {
		if _, duplicate := seen[member.Value]; duplicate {
			continue
		}
		seen[member.Value] = struct{}{}
		result = append(result, member)
	}
	return result
}

func ensureEnterprise(user *scimmodel.User) {
	if user.EnterpriseUser == nil {
		user.EnterpriseUser = &scimmodel.EnterpriseUser{}
	}
}

func removedOrString(op string, value any) string {
	if op == "remove" {
		return ""
	}
	return stringValue(value)
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func decodeValue(value any, target any, label string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return invalidValue(label + " is invalid")
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return invalidValue(label + " has an invalid shape")
	}
	return nil
}
