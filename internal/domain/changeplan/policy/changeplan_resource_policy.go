package policy

import "strings"

func ChangePlanCanonicalResourceType(resourceType string) string {
	return strings.TrimSpace(resourceType)
}
