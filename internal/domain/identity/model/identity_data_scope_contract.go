package identitymodel

// AuthoringDataScopeValues is the only builder/runtime contract for role
// data-scope authoring and evaluation.
func AuthoringDataScopeValues() []string {
	return []string{"all_records", "custom", "organization", "organization_and_children", "self_and_subordinates", "none", "owned_records"}
}

func CanonicalIdentityDataScope(value string) (IdentityDataScope, bool) {
	switch value {
	case "all_records", "owned_records", "organization", "organization_and_children", "self_and_subordinates", "custom", "none":
		return IdentityDataScope(value), true
	default:
		return "", false
	}
}
