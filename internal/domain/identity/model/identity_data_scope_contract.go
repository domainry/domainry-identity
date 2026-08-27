package identitymodel

// AuthoringDataScopeValues is the only builder/runtime contract for role
// data-scope authoring and evaluation.
func AuthoringDataScopeValues() []string {
	return []string{"all_records", "custom", "department", "department_and_children", "none", "owned_records", "subordinates", "team"}
}

func CanonicalIdentityDataScope(value string) (IdentityDataScope, bool) {
	switch value {
	case "all_records", "owned_records", "team", "subordinates", "department", "department_and_children", "custom", "none":
		return IdentityDataScope(value), true
	default:
		return "", false
	}
}
