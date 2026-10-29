package identitymodel

const (
	IdentityPermissionDefinitionActive  = "active"
	IdentityPermissionDefinitionRetired = "retired"
)

// IdentityPermissionDefinitionRecord is the current, reconciled permission
// configuration persisted by Identity. Executable Action bindings and their
// governance metadata deliberately do not live in this record.
type IdentityPermissionDefinitionRecord struct {
	PermissionKey      string                          `json:"permission_key"`
	ModuleKey          string                          `json:"module_key"`
	GroupKey           string                          `json:"group_key"`
	ResourceKey        string                          `json:"resource_key"`
	OperationKey       string                          `json:"operation_key"`
	Label              string                          `json:"label"`
	Description        string                          `json:"description,omitempty"`
	Category           string                          `json:"category"`
	SourceKind         string                          `json:"source_kind"`
	SourceOwner        string                          `json:"source_owner"`
	GrantMode          string                          `json:"grant_mode"`
	ScopeKind          string                          `json:"scope_kind"`
	ObjectKey          string                          `json:"object_key,omitempty"`
	DefaultLocale      string                          `json:"default_locale"`
	I18n               IdentityPermissionLocalizedText `json:"i18n"`
	DefinitionStatus   string                          `json:"definition_status"`
	Enabled            bool                            `json:"enabled"`
	DefinitionHash     string                          `json:"definition_hash"`
	SourceSnapshotHash string                          `json:"source_snapshot_hash"`
	CreatedAt          string                          `json:"created_at"`
	UpdatedAt          string                          `json:"updated_at"`
}

type IdentityPermissionText struct {
	ModuleLabel    string `json:"module_label"`
	GroupLabel     string `json:"group_label"`
	ResourceLabel  string `json:"resource_label"`
	OperationLabel string `json:"operation_label"`
	Label          string `json:"label"`
	Description    string `json:"description,omitempty"`
}

type IdentityPermissionLocalizedText map[string]IdentityPermissionText

type IdentityPermissionReconcileRequest struct {
	SourceOwner          string
	PreviousSnapshotHash string
	SnapshotHash         string
	Definitions          []IdentityPermissionDefinitionRecord
}

type IdentityPermissionReconcileReceipt struct {
	SourceOwner          string `json:"source_owner"`
	PreviousSnapshotHash string `json:"previous_snapshot_hash,omitempty"`
	SnapshotHash         string `json:"snapshot_hash"`
	DefinitionCount      int    `json:"definition_count"`
	Inserted             int    `json:"inserted"`
	Updated              int    `json:"updated"`
	Retired              int    `json:"retired"`
	Unchanged            int    `json:"unchanged"`
}
