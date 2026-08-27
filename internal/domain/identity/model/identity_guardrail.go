package identitymodel

// IdentityGuardrailPolicy is a reusable deny-only restriction. Positive grants
// remain in Permission Sets; a matching guardrail always wins.
type IdentityGuardrailPolicy struct {
	Key                  string                     `json:"key"`
	Name                 string                     `json:"name"`
	Description          string                     `json:"description,omitempty"`
	DeniedPermissionKeys []string                   `json:"denied_permission_keys,omitempty"`
	DataRestrictions     []IdentityDataRestriction  `json:"data_restrictions,omitempty"`
	FieldRestrictions    []IdentityFieldRestriction `json:"field_restrictions,omitempty"`
}

type IdentityDataRestriction struct {
	ObjectKey string   `json:"object_key"`
	Actions   []string `json:"actions"`
	Reason    string   `json:"reason,omitempty"`
}

type IdentityFieldRestriction struct {
	ObjectKey string   `json:"object_key"`
	FieldKey  string   `json:"field_key"`
	Actions   []string `json:"actions"`
	Reason    string   `json:"reason,omitempty"`
}
