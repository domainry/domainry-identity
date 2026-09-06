package identitymodel

// IdentityWorkspaceUsageGroup is one database-produced aggregate bucket. It
// intentionally has no user-level fields.
type IdentityWorkspaceUsageGroup struct {
	WorkspaceID string
	AccountType IdentityAccountType
	Status      IdentityStatus
	Count       int64
}

// IdentityWorkspaceActiveHumanRoleCount is a database-produced scalar per
// Workspace. Persistence de-duplicates users before counting and never returns
// a user identifier to the application layer.
type IdentityWorkspaceActiveHumanRoleCount struct {
	WorkspaceID string
	Count       int64
}

type IdentityWorkspaceAccountCounts struct {
	ActiveHumanAccounts               int64
	ActiveHumanAccountsWithActiveRole int64
	DisabledHumanAccounts             int64
	ServiceAccounts                   int64
	AutomationAccounts                int64
}

type IdentityWorkspaceUsage struct {
	WorkspaceID string
	Accounts    IdentityWorkspaceAccountCounts
}

type IdentityWorkspaceUsagePage struct {
	Items      []IdentityWorkspaceUsage
	NextCursor string
}

type IdentityWorkspaceUsageGrant struct {
	InstallationID        string
	ApplicationKey        string
	SubjectID             string
	AuditWorkspaceID      string
	PermissionKey         string
	AuthorizationRevision string
	AuthorizationAuditID  string
}

type IdentityWorkspaceUsageCatalogEntry struct {
	WorkspaceID string
	Status      string
	Known       bool
	Authorized  bool
}

type IdentityWorkspaceUsageCatalogPage struct {
	CatalogRevision string
	Workspaces      []IdentityWorkspaceUsageCatalogEntry
}
