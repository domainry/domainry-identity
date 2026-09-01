package identitymodel

const (
	IdentityPermissionDefinitionActive  = "active"
	IdentityPermissionDefinitionRetired = "retired"
)

// IdentityPermissionDefinitionRecord is the current, reconciled permission
// configuration persisted by Identity. Executable Action bindings and their
// governance metadata deliberately do not live in this record.
type IdentityPermissionDefinitionRecord struct {
	ID                 string `json:"id"`
	WorkspaceID        string `json:"workspace_id"`
	PermissionKey      string `json:"permission_key"`
	ResourceKey        string `json:"resource_key"`
	ActionKey          string `json:"action_key"`
	Label              string `json:"label"`
	Description        string `json:"description,omitempty"`
	Category           string `json:"category"`
	SourceKind         string `json:"source_kind"`
	SourceOwner        string `json:"source_owner"`
	DefinitionStatus   string `json:"definition_status"`
	Enabled            bool   `json:"enabled"`
	DefinitionHash     string `json:"definition_hash"`
	SourceSnapshotHash string `json:"source_snapshot_hash"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type IdentityPermissionReconcileRequest struct {
	WorkspaceID          string
	SourceOwner          string
	PreviousSnapshotHash string
	SnapshotHash         string
	Definitions          []IdentityPermissionDefinitionRecord
}

type IdentityPermissionReconcileReceipt struct {
	WorkspaceID  string `json:"workspace_id"`
	SourceOwner  string `json:"source_owner"`
	SnapshotHash string `json:"snapshot_hash"`
	Inserted     int    `json:"inserted"`
	Updated      int    `json:"updated"`
	Retired      int    `json:"retired"`
	Unchanged    int    `json:"unchanged"`
}
