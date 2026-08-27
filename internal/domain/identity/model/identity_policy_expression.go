package identitymodel

// IdentityPolicyExpression is the only published custom RLS predicate.
// Relation paths are explicit so Manifest validation and SQL compilation use
// the same graph instead of interpreting free-form filter strings.
type IdentityPolicyExpression struct {
	Operator    string                          `json:"operator"`
	Path        []IdentityPolicyRelationSegment `json:"path,omitempty"`
	FieldKey    string                          `json:"field_key,omitempty"`
	ValueSource string                          `json:"value_source,omitempty"`
	ClaimKey    string                          `json:"claim_key,omitempty"`
	Values      []string                        `json:"values,omitempty"`
	Children    []IdentityPolicyExpression      `json:"children,omitempty"`
}

type IdentityPolicyRelationSegment struct {
	Direction        string `json:"direction"`
	RelationFieldKey string `json:"relation_field_key"`
	TargetObjectKey  string `json:"target_object_key"`
}

// ContextualFieldPolicyRule refines one field's unconditional permission using
// the same typed record/relationship predicate used by RLS.
type ContextualFieldPolicyRule struct {
	Key          string                    `json:"key"`
	Priority     int                       `json:"priority"`
	Actions      []string                  `json:"actions"`
	Effect       string                    `json:"effect"`
	Predicate    *IdentityPolicyExpression `json:"predicate,omitempty"`
	MaskStrategy *FieldMaskStrategy        `json:"mask_strategy,omitempty"`
	AuditDenial  bool                      `json:"audit_denial,omitempty"`
}

type FieldMaskStrategy struct {
	Type  string `json:"type"`
	LastN int    `json:"last_n,omitempty"`
}
