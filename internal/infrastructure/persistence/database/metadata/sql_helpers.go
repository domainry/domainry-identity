package metadata

import (
	"strings"
)

func dbValue(value any) any {
	switch typed := value.(type) {
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	default:
		return value
	}
}

func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
