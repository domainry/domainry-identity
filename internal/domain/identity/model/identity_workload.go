package identitymodel

type IdentityWorkflowWorkloadBinding struct {
	WorkspaceID         string
	ApplicationKey      string
	SubjectID           string
	WorkflowKey         string
	DefinitionVersionID string
	DefinitionVersion   int
	RoleKey             string
	ActionKeys          []string
	ReleaseID           string
	ReleaseDigest       string
	SourceKind          string
	SourceID            string
	Status              string
	CreatedAt           string
	UpdatedAt           string
	DeactivatedAt       string
}

type IdentityWorkflowWorkloadRelease struct {
	WorkspaceID    string
	ApplicationKey string
	ReleaseID      string
	ReleaseDigest  string
	Bindings       []IdentityWorkflowWorkloadBinding
}
