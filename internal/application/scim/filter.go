package scim

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

type AttributeValues map[string][]any

func UserAttributeValues(user scimmodel.User) AttributeValues {
	values := AttributeValues{
		"id": {user.ID}, "externalid": optionalStringValue(user.ExternalID), "username": {user.UserName},
		"displayname": optionalStringValue(user.DisplayName), "name": {}, "name.formatted": optionalStringValue(user.Name.Formatted),
		"name.givenname": optionalStringValue(user.Name.GivenName), "name.familyname": optionalStringValue(user.Name.FamilyName),
		"name.middlename": optionalStringValue(user.Name.MiddleName), "name.honorificprefix": optionalStringValue(user.Name.HonorificPrefix),
		"name.honorificsuffix": optionalStringValue(user.Name.HonorificSuffix), "preferredlanguage": optionalStringValue(user.PreferredLang),
		"locale": optionalStringValue(user.Locale), "timezone": optionalStringValue(user.Timezone), "schemas": stringValues(user.Schemas),
		"meta.resourcetype": optionalStringValue(user.Meta.ResourceType), "meta.created": optionalStringValue(user.Meta.Created),
		"meta.lastmodified": optionalStringValue(user.Meta.LastModified), "meta.version": optionalStringValue(user.Meta.Version), "meta.location": optionalStringValue(user.Meta.Location),
		"active": {}, "emails": {}, "emails.value": {}, "emails.type": {}, "emails.primary": {}, "emails.$complex": {},
		"phonenumbers": {}, "phonenumbers.value": {}, "phonenumbers.type": {}, "phonenumbers.primary": {}, "phonenumbers.$complex": {},
	}
	if presentName(user.Name) {
		values["name"] = []any{map[string]any{"formatted": user.Name.Formatted, "givenName": user.Name.GivenName, "familyName": user.Name.FamilyName}}
	}
	if user.Active != nil {
		values["active"] = []any{*user.Active}
	}
	for _, email := range user.Emails {
		values["emails"] = append(values["emails"], email.Value)
		values["emails.value"] = append(values["emails.value"], email.Value)
		values["emails.type"] = append(values["emails.type"], email.Type)
		values["emails.primary"] = append(values["emails.primary"], email.Primary)
		values["emails.$complex"] = append(values["emails.$complex"], map[string]any{"value": email.Value, "type": email.Type, "primary": email.Primary})
	}
	for _, phone := range user.PhoneNumbers {
		values["phonenumbers"] = append(values["phonenumbers"], phone.Value)
		values["phonenumbers.value"] = append(values["phonenumbers.value"], phone.Value)
		values["phonenumbers.type"] = append(values["phonenumbers.type"], phone.Type)
		values["phonenumbers.primary"] = append(values["phonenumbers.primary"], phone.Primary)
		values["phonenumbers.$complex"] = append(values["phonenumbers.$complex"], map[string]any{"value": phone.Value, "type": phone.Type, "primary": phone.Primary})
	}
	const enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:"
	values[enterprise+"employeenumber"] = []any{}
	values[enterprise+"department"] = []any{}
	values[enterprise+"manager"] = []any{}
	values[enterprise+"manager.value"] = []any{}
	values[enterprise+"manager.$ref"] = []any{}
	values[enterprise+"manager.displayname"] = []any{}
	values[strings.TrimSuffix(enterprise, ":")] = []any{}
	if user.EnterpriseUser != nil {
		values[strings.TrimSuffix(enterprise, ":")] = []any{map[string]any{}}
		values[enterprise+"employeenumber"] = optionalStringValue(user.EnterpriseUser.EmployeeNumber)
		values[enterprise+"department"] = optionalStringValue(user.EnterpriseUser.Department)
		if user.EnterpriseUser.Manager != nil {
			values[enterprise+"manager"] = []any{map[string]any{}}
			values[enterprise+"manager.value"] = optionalStringValue(user.EnterpriseUser.Manager.Value)
			values[enterprise+"manager.$ref"] = optionalStringValue(user.EnterpriseUser.Manager.Ref)
			values[enterprise+"manager.displayname"] = optionalStringValue(user.EnterpriseUser.Manager.DisplayName)
		}
	}
	return values
}

func GroupAttributeValues(group scimmodel.Group) AttributeValues {
	values := AttributeValues{
		"id": {group.ID}, "externalid": optionalStringValue(group.ExternalID), "displayname": {group.DisplayName}, "schemas": stringValues(group.Schemas),
		"meta.resourcetype": optionalStringValue(group.Meta.ResourceType), "meta.created": optionalStringValue(group.Meta.Created), "meta.lastmodified": optionalStringValue(group.Meta.LastModified), "meta.version": optionalStringValue(group.Meta.Version), "meta.location": optionalStringValue(group.Meta.Location),
		"members": {}, "members.value": {}, "members.display": {}, "members.type": {}, "members.$ref": {}, "members.$complex": {},
	}
	for _, member := range group.Members {
		values["members"] = append(values["members"], member.Value)
		values["members.value"] = append(values["members.value"], member.Value)
		values["members.display"] = append(values["members.display"], member.Display)
		values["members.type"] = append(values["members.type"], member.Type)
		values["members.$ref"] = append(values["members.$ref"], member.Ref)
		values["members.$complex"] = append(values["members.$complex"], map[string]any{"value": member.Value, "display": member.Display, "type": member.Type, "$ref": member.Ref})
	}
	return values
}

func optionalStringValue(value string) []any {
	if strings.TrimSpace(value) == "" {
		return []any{}
	}
	return []any{value}
}

func presentName(name scimmodel.Name) bool {
	return strings.TrimSpace(name.Formatted+name.FamilyName+name.GivenName+name.MiddleName+name.HonorificPrefix+name.HonorificSuffix) != ""
}

func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}

func MatchFilter(raw string, values AttributeValues) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true, nil
	}
	parser, err := newFilterParser(raw)
	if err != nil {
		return false, err
	}
	expression, err := parser.parse()
	if err != nil {
		return false, err
	}
	return expression.match(values)
}

type filterExpression interface {
	match(AttributeValues) (bool, error)
}

type logicalExpression struct {
	op          string
	left, right filterExpression
}

func (expression logicalExpression) match(values AttributeValues) (bool, error) {
	left, err := expression.left.match(values)
	if err != nil {
		return false, err
	}
	if expression.op == "and" && !left {
		return false, nil
	}
	if expression.op == "or" && left {
		return true, nil
	}
	right, err := expression.right.match(values)
	if err != nil {
		return false, err
	}
	if expression.op == "and" {
		return left && right, nil
	}
	return left || right, nil
}

type notExpression struct{ child filterExpression }

func (expression notExpression) match(values AttributeValues) (bool, error) {
	matched, err := expression.child.match(values)
	return !matched, err
}

type valuePathExpression struct {
	attribute string
	child     filterExpression
}

func (expression valuePathExpression) match(values AttributeValues) (bool, error) {
	attribute := normalizeFilterAttribute(expression.attribute)
	candidates, known := values[attribute+".$complex"]
	if !known {
		return false, invalidFilter("filter references an unsupported multi-valued attribute: " + expression.attribute)
	}
	for _, candidate := range candidates {
		object, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		relative := AttributeValues{}
		for key, value := range object {
			relative[strings.ToLower(key)] = []any{value}
		}
		matched, err := expression.child.match(relative)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

type comparisonExpression struct {
	attribute string
	op        string
	value     any
}

func (expression comparisonExpression) match(values AttributeValues) (bool, error) {
	candidates, known := values[normalizeFilterAttribute(expression.attribute)]
	if !known {
		return false, invalidFilter("filter references an unsupported attribute: " + expression.attribute)
	}
	if expression.op == "pr" {
		for _, candidate := range candidates {
			if present(candidate) {
				return true, nil
			}
		}
		return false, nil
	}
	if expression.op == "ne" {
		for _, candidate := range candidates {
			equal, err := compareFilterValue(candidate, expression.value, "eq")
			if err != nil {
				return false, err
			}
			if equal {
				return false, nil
			}
		}
		return len(candidates) > 0, nil
	}
	for _, candidate := range candidates {
		matched, err := compareFilterValue(candidate, expression.value, expression.op)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func normalizeFilterAttribute(attribute string) string {
	attribute = strings.TrimSpace(attribute)
	for _, schema := range []string{scimmodel.SchemaUser, scimmodel.SchemaGroup} {
		if len(attribute) > len(schema) && strings.EqualFold(attribute[:len(schema)], schema) && attribute[len(schema)] == ':' {
			attribute = attribute[len(schema)+1:]
			break
		}
	}
	return strings.ToLower(attribute)
}

func present(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	default:
		return true
	}
}

func compareFilterValue(left, right any, operator string) (bool, error) {
	if leftBool, ok := left.(bool); ok {
		rightBool, valid := right.(bool)
		if !valid || operator != "eq" && operator != "ne" {
			return false, invalidFilter("boolean attributes only support eq and ne")
		}
		if operator == "eq" {
			return leftBool == rightBool, nil
		}
		return leftBool != rightBool, nil
	}
	leftText := strings.ToLower(fmt.Sprint(left))
	rightText := strings.ToLower(fmt.Sprint(right))
	switch operator {
	case "eq":
		return leftText == rightText, nil
	case "ne":
		return leftText != rightText, nil
	case "co":
		return strings.Contains(leftText, rightText), nil
	case "sw":
		return strings.HasPrefix(leftText, rightText), nil
	case "ew":
		return strings.HasSuffix(leftText, rightText), nil
	case "gt":
		return leftText > rightText, nil
	case "ge":
		return leftText >= rightText, nil
	case "lt":
		return leftText < rightText, nil
	case "le":
		return leftText <= rightText, nil
	default:
		return false, invalidFilter("unsupported filter operator: " + operator)
	}
}

type filterToken struct {
	kind string
	text string
}

type filterParser struct {
	tokens []filterToken
	index  int
}

func newFilterParser(raw string) (*filterParser, error) {
	tokens, err := tokenizeFilter(raw)
	if err != nil {
		return nil, err
	}
	return &filterParser{tokens: tokens}, nil
}

func (parser *filterParser) parse() (filterExpression, error) {
	expression, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if parser.index != len(parser.tokens) {
		return nil, invalidFilter("filter contains unexpected input near " + parser.tokens[parser.index].text)
	}
	return expression, nil
}

func (parser *filterParser) parseOr() (filterExpression, error) {
	left, err := parser.parseAnd()
	if err != nil {
		return nil, err
	}
	for parser.acceptWord("or") {
		right, err := parser.parseAnd()
		if err != nil {
			return nil, err
		}
		left = logicalExpression{op: "or", left: left, right: right}
	}
	return left, nil
}

func (parser *filterParser) parseAnd() (filterExpression, error) {
	left, err := parser.parseUnary()
	if err != nil {
		return nil, err
	}
	for parser.acceptWord("and") {
		right, err := parser.parseUnary()
		if err != nil {
			return nil, err
		}
		left = logicalExpression{op: "and", left: left, right: right}
	}
	return left, nil
}

func (parser *filterParser) parseUnary() (filterExpression, error) {
	if parser.acceptWord("not") {
		child, err := parser.parseUnary()
		return notExpression{child: child}, err
	}
	if parser.acceptKind("(") {
		expression, err := parser.parseOr()
		if err != nil {
			return nil, err
		}
		if !parser.acceptKind(")") {
			return nil, invalidFilter("filter is missing a closing parenthesis")
		}
		return expression, nil
	}
	return parser.parseComparison()
}

func (parser *filterParser) parseComparison() (filterExpression, error) {
	attribute, ok := parser.take("word")
	if !ok {
		return nil, invalidFilter("filter attribute is required")
	}
	if parser.acceptKind("[") {
		child, err := parser.parseOr()
		if err != nil {
			return nil, err
		}
		if !parser.acceptKind("]") {
			return nil, invalidFilter("filter valuePath is missing a closing bracket")
		}
		return valuePathExpression{attribute: attribute.text, child: child}, nil
	}
	operator, ok := parser.take("word")
	if !ok {
		return nil, invalidFilter("filter operator is required")
	}
	operator.text = strings.ToLower(operator.text)
	if operator.text == "pr" {
		return comparisonExpression{attribute: attribute.text, op: operator.text}, nil
	}
	if !isComparisonOperator(operator.text) {
		return nil, invalidFilter("unsupported filter operator: " + operator.text)
	}
	value, ok := parser.takeAny("string", "word")
	if !ok {
		return nil, invalidFilter("filter comparison value is required")
	}
	parsedValue := any(value.text)
	if value.kind == "word" {
		switch strings.ToLower(value.text) {
		case "true":
			parsedValue = true
		case "false":
			parsedValue = false
		case "null":
			parsedValue = nil
		}
	}
	return comparisonExpression{attribute: attribute.text, op: operator.text, value: parsedValue}, nil
}

func isComparisonOperator(value string) bool {
	switch value {
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
		return true
	default:
		return false
	}
}

func (parser *filterParser) acceptWord(value string) bool {
	if parser.index < len(parser.tokens) && parser.tokens[parser.index].kind == "word" && strings.EqualFold(parser.tokens[parser.index].text, value) {
		parser.index++
		return true
	}
	return false
}

func (parser *filterParser) acceptKind(kind string) bool {
	if parser.index < len(parser.tokens) && parser.tokens[parser.index].kind == kind {
		parser.index++
		return true
	}
	return false
}

func (parser *filterParser) take(kind string) (filterToken, bool) {
	if parser.index >= len(parser.tokens) || parser.tokens[parser.index].kind != kind {
		return filterToken{}, false
	}
	token := parser.tokens[parser.index]
	parser.index++
	return token, true
}

func (parser *filterParser) takeAny(kinds ...string) (filterToken, bool) {
	for _, kind := range kinds {
		if token, ok := parser.take(kind); ok {
			return token, true
		}
	}
	return filterToken{}, false
}

func tokenizeFilter(raw string) ([]filterToken, error) {
	tokens := []filterToken{}
	for index := 0; index < len(raw); {
		r := rune(raw[index])
		if unicode.IsSpace(r) {
			index++
			continue
		}
		if raw[index] == '(' || raw[index] == ')' || raw[index] == '[' || raw[index] == ']' {
			tokens = append(tokens, filterToken{kind: string(raw[index]), text: string(raw[index])})
			index++
			continue
		}
		if raw[index] == '"' {
			start := index
			index++
			escaped := false
			for index < len(raw) {
				if raw[index] == '"' && !escaped {
					index++
					break
				}
				if raw[index] == '\\' && !escaped {
					escaped = true
				} else {
					escaped = false
				}
				index++
			}
			if index > len(raw) || raw[index-1] != '"' {
				return nil, invalidFilter("filter contains an unterminated string")
			}
			value, err := strconv.Unquote(raw[start:index])
			if err != nil {
				return nil, invalidFilter("filter contains an invalid string")
			}
			tokens = append(tokens, filterToken{kind: "string", text: value})
			continue
		}
		start := index
		for index < len(raw) && !unicode.IsSpace(rune(raw[index])) && raw[index] != '(' && raw[index] != ')' && raw[index] != '[' && raw[index] != ']' {
			index++
		}
		if start == index {
			return nil, invalidFilter("filter contains invalid syntax")
		}
		tokens = append(tokens, filterToken{kind: "word", text: raw[start:index]})
	}
	if len(tokens) == 0 {
		return nil, invalidFilter("filter is empty")
	}
	return tokens, nil
}
