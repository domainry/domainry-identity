package identitymodel

type BusinessIdentityClaimBinding struct {
	ClaimKey string `json:"claim_key"`
	FieldKey string `json:"field_key"`
}

type BusinessIdentityBinding struct {
	Key                string                         `json:"key"`
	StatusField        string                         `json:"status_field,omitempty"`
	ActiveStatusValues []string                       `json:"active_status_values,omitempty"`
	BlacklistField     string                         `json:"blacklist_field,omitempty"`
	Claims             []BusinessIdentityClaimBinding `json:"claims,omitempty"`
}

type IdentityProfileClaimProof struct {
	Type     string `json:"type"`
	FieldKey string `json:"field_key"`
}

type IdentityProfileBindingLifecycle struct {
	AllowUnbound           bool                        `json:"allow_unbound,omitempty"`
	InvitationChannels     []string                    `json:"invitation_channels,omitempty"`
	ClaimProofs            []IdentityProfileClaimProof `json:"claim_proofs,omitempty"`
	RebindRequiresApproval bool                        `json:"rebind_requires_approval,omitempty"`
	RebindRevokesSessions  bool                        `json:"rebind_revokes_sessions,omitempty"`
}

// IdentityProfileExtension is the Runtime-native discovery contract that joins
// one domain profile object to a global Identity user.
type IdentityProfileExtension struct {
	ObjectKey             string                          `json:"object_key"`
	IdentityRelationField string                          `json:"identity_relation_field"`
	Cardinality           string                          `json:"cardinality"`
	BusinessIdentity      BusinessIdentityBinding         `json:"business_identity"`
	BindingLifecycle      IdentityProfileBindingLifecycle `json:"binding_lifecycle,omitempty"`
	DefaultVisibility     string                          `json:"default_visibility"`
	RequiredPermissions   []string                        `json:"required_permissions,omitempty"`
}
