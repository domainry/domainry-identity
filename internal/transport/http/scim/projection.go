package scimhttp

import (
	"encoding/json"
	"net/http"
	"strings"

	scimapplication "github.com/domainry/domainry-identity/internal/application/scim"
	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
)

type responseAttributePath struct {
	top string
	sub string
}

func projectResponseAttributes(request *http.Request, value any) (any, error) {
	includeRaw := strings.Join(request.URL.Query()["attributes"], ",")
	excludeRaw := strings.Join(request.URL.Query()["excludedAttributes"], ",")
	if strings.TrimSpace(includeRaw) != "" && strings.TrimSpace(excludeRaw) != "" {
		return nil, &scimapplication.Error{Status: http.StatusBadRequest, SCIMType: "invalidValue", Detail: "attributes and excludedAttributes are mutually exclusive"}
	}
	if strings.TrimSpace(includeRaw) == "" && strings.TrimSpace(excludeRaw) == "" {
		return value, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, err
	}
	if strings.TrimSpace(includeRaw) != "" {
		projected := map[string]any{}
		copyAlwaysReturned(object, projected, "schemas")
		copyAlwaysReturned(object, projected, "id")
		for _, path := range parseResponseAttributePaths(includeRaw) {
			copyResponseAttribute(object, projected, path)
		}
		normalizeProjectedSchemas(projected)
		return projected, nil
	}
	for _, path := range parseResponseAttributePaths(excludeRaw) {
		removeResponseAttribute(object, path)
	}
	normalizeProjectedSchemas(object)
	return object, nil
}

func parseResponseAttributePaths(raw string) []responseAttributePath {
	paths := []responseAttributePath{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		path := responseAttributePath{}
		for _, schema := range []string{scimmodel.SchemaEnterpriseUser, scimmodel.SchemaUser, scimmodel.SchemaGroup} {
			if strings.EqualFold(item, schema) {
				path.top = schema
				break
			}
			if len(item) > len(schema) && strings.EqualFold(item[:len(schema)], schema) && item[len(schema)] == ':' {
				path.top, path.sub = schema, item[len(schema)+1:]
				break
			}
		}
		if path.top == "" {
			path.top, path.sub, _ = strings.Cut(item, ".")
		}
		paths = append(paths, path)
	}
	return paths
}

func copyAlwaysReturned(source, target map[string]any, key string) {
	if actual, found := responseKey(source, key); found {
		target[actual] = source[actual]
	}
}

func copyResponseAttribute(source, target map[string]any, path responseAttributePath) {
	actual, found := responseKey(source, path.top)
	if !found {
		return
	}
	if path.sub == "" {
		target[actual] = source[actual]
		return
	}
	projected, ok := projectNestedValue(source[actual], strings.Split(path.sub, "."))
	if !ok {
		return
	}
	target[actual] = mergeProjectedValues(target[actual], projected)
}

func removeResponseAttribute(object map[string]any, path responseAttributePath) {
	if strings.EqualFold(path.top, "schemas") || strings.EqualFold(path.top, "id") {
		return
	}
	actual, found := responseKey(object, path.top)
	if !found {
		return
	}
	if path.sub == "" {
		delete(object, actual)
		return
	}
	if removeNestedValue(object[actual], strings.Split(path.sub, ".")) {
		delete(object, actual)
	}
}

func projectNestedValue(value any, path []string) (any, bool) {
	if len(path) == 0 {
		return value, true
	}
	switch typed := value.(type) {
	case map[string]any:
		key, found := responseKey(typed, path[0])
		if !found {
			return nil, false
		}
		projected, found := projectNestedValue(typed[key], path[1:])
		if !found {
			return nil, false
		}
		return map[string]any{key: projected}, true
	case []any:
		projected := make([]any, 0, len(typed))
		for _, item := range typed {
			value, found := projectNestedValue(item, path)
			if found {
				projected = append(projected, value)
			}
		}
		return projected, len(projected) != 0
	default:
		return nil, false
	}
}

func mergeProjectedValues(existing, addition any) any {
	if existing == nil {
		return addition
	}
	switch left := existing.(type) {
	case map[string]any:
		right, ok := addition.(map[string]any)
		if !ok {
			return addition
		}
		for key, value := range right {
			left[key] = mergeProjectedValues(left[key], value)
		}
		return left
	case []any:
		right, ok := addition.([]any)
		if !ok || len(left) != len(right) {
			return addition
		}
		for index := range left {
			left[index] = mergeProjectedValues(left[index], right[index])
		}
		return left
	default:
		return addition
	}
}

// removeNestedValue returns true when the containing top-level value became
// empty and should be removed as well.
func removeNestedValue(value any, path []string) bool {
	if len(path) == 0 {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		key, found := responseKey(typed, path[0])
		if !found {
			return len(typed) == 0
		}
		if len(path) == 1 || removeNestedValue(typed[key], path[1:]) {
			delete(typed, key)
		}
		return len(typed) == 0
	case []any:
		for _, item := range typed {
			_ = removeNestedValue(item, path)
		}
		return len(typed) == 0
	default:
		return false
	}
}

func responseKey(object map[string]any, wanted string) (string, bool) {
	for key := range object {
		if strings.EqualFold(key, wanted) {
			return key, true
		}
	}
	return "", false
}

func normalizeProjectedSchemas(object map[string]any) {
	key, found := responseKey(object, "schemas")
	if !found {
		return
	}
	values, ok := object[key].([]any)
	if !ok {
		return
	}
	filtered := make([]any, 0, len(values))
	for _, value := range values {
		schema, _ := value.(string)
		if schema == scimmodel.SchemaEnterpriseUser {
			if _, present := responseKey(object, schema); !present {
				continue
			}
		}
		filtered = append(filtered, value)
	}
	object[key] = filtered
}
