package schema

import (
	"sort"

	"github.com/domainry/domainry-foundation/schemaownership"
)

const MigrationOwner = "identity"

type TableBoundary string

const (
	TableBoundarySchemaControl  TableBoundary = "schema_control"
	TableBoundaryIdentityCore   TableBoundary = "identity_core"
	TableBoundaryProfileBinding TableBoundary = "profile_binding"
	TableBoundaryAuthorization  TableBoundary = "authorization"
	TableBoundaryAuthentication TableBoundary = "authentication"
	TableBoundaryMetadata       TableBoundary = "metadata_governance"
	TableBoundaryEvidence       TableBoundary = "audit_and_contract_evidence"
)

type MigrationDisposition string

const (
	MigrationPortable         MigrationDisposition = "portable"
	MigrationEvidenceOnly     MigrationDisposition = "evidence_only"
	MigrationKeyReferenceOnly MigrationDisposition = "key_reference_only"
	MigrationExcluded         MigrationDisposition = "excluded"
)

// TableOwnership is the executable source of truth for data owned by
// Identity. MigrationDisposition applies to Embedded-to-SaaS migration and
// prevents ephemeral credentials or secret material from entering a portable
// tenant export by accident.
type TableOwnership struct {
	Name                 string
	Boundary             TableBoundary
	MigrationDisposition MigrationDisposition
	ContainsSecret       bool
}

var identityTableOwnership = []TableOwnership{
	{Name: "_identity_auth_assertion_replays", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_authorization_codes", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_login_transactions", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_otp_delivery_limits", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_provider_credentials", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationKeyReferenceOnly, ContainsSecret: true},
	{Name: "_identity_auth_refresh_tokens", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_access_review_items", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_access_reviews", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_applications", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationPortable},
	{Name: "_identity_credentials", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_organization_units", Boundary: TableBoundaryIdentityCore, MigrationDisposition: MigrationPortable},
	{Name: "_identity_external_accounts", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationPortable},
	{Name: "_identity_menus", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_permissions", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_mfa_factors", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_profile_bindings", Boundary: TableBoundaryProfileBinding, MigrationDisposition: MigrationPortable},
	{Name: "_identity_role_menu_assignments", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_role_requests", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_roles", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_user_role_assignments", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_workflow_workload_bindings", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_users", Boundary: TableBoundaryIdentityCore, MigrationDisposition: MigrationPortable},
}

var schemaTableOwnership = []schemaownership.Table{
	owned("_identity_access_review_items", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/review item identity and bounded review or governed-user listing", "review deletion removes its items; subject erasure redacts governed-user references through Identity lifecycle"),
	owned("_identity_access_reviews", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/review identity and bounded status/due-date listing", "completed reviews follow Identity governance retention; explicit review deletion removes the aggregate and items"),
	owned("_identity_applications", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/application identity and exact application-key lookup", "application removal deletes the registration after dependent authorization state is revoked"),
	owned("_identity_auth_assertion_replays", schemaownership.RetentionTechnicalTTL, []string{"workspace_id", "replay_hash"}, "workspace/assertion hash identity and bounded expiry cleanup", "expired assertion claims are physically purged after the replay-defense window"),
	owned("_identity_auth_authorization_codes", schemaownership.RetentionTechnicalTTL, []string{"workspace_id", "code_hash"}, "workspace/code hash identity with atomic one-time consume", "consumed and expired authorization codes are physically purged after the protocol replay window"),
	owned("_identity_auth_login_transactions", schemaownership.RetentionTechnicalTTL, []string{"workspace_id", "state_hash"}, "global state-hash resolution followed by workspace/provider consume and bounded subject challenge lookup", "consumed and expired login transactions are physically purged after the authentication window"),
	owned("_identity_auth_otp_delivery_limits", schemaownership.RetentionTechnicalTTL, []string{"workspace_id", "subject_key_hash"}, "workspace/provider/subject delivery throttle identity", "expired delivery throttle rows are physically purged after their rate-limit window"),
	owned("_identity_auth_provider_credentials", schemaownership.RetentionInstallation, []string{"workspace_id", "provider_key"}, "exact workspace/provider configuration identity", "provider removal physically deletes encrypted configuration after active authentication flows are fenced"),
	owned("_identity_auth_refresh_tokens", schemaownership.RetentionTechnicalTTL, []string{"workspace_id", "id"}, "global token-hash resolution, workspace/session identity and replacement-chain lookup", "logout and reuse revoke the chain; expired terminal tokens are physically purged"),
	owned("_identity_credentials", schemaownership.RetentionUserErase, []string{"workspace_id", "user_id"}, "exact workspace/user credential identity", "user erasure physically removes the password hash and lockout state"),
	owned("_identity_external_accounts", schemaownership.RetentionUserErase, []string{"workspace_id", "id"}, "workspace/external-account identity and provider-subject or user lookup", "unlinking or user erasure physically removes the external identity mapping"),
	owned("_identity_menus", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/menu identity, menu-key lookup and bounded hierarchy listing", "menu deletion removes assignments before removing the menu row"),
	owned("_identity_mfa_factors", schemaownership.RetentionUserErase, []string{"workspace_id", "id"}, "workspace/factor identity and bounded user-factor lookup", "factor removal or user erasure physically removes factor secret and replay state"),
	owned("_identity_organization_units", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/unit identity, code identity and bounded hierarchy traversal", "organization-unit deletion is rejected while governed users or children remain"),
	owned("_identity_permissions", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/permission identity and bounded source-owner or definition-state listing", "definition reconciliation disables or removes permissions after role references are reconciled"),
	owned("_identity_profile_bindings", schemaownership.RetentionUserErase, []string{"workspace_id", "id"}, "workspace/binding identity and exact profile or user binding lookup", "profile unlinking or subject erasure removes the binding after Audit history is recorded"),
	owned("_identity_role_menu_assignments", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace assignment identity and bounded role-to-menu or menu-to-role lookup", "role or menu deletion physically removes dependent assignments"),
	owned("_identity_role_requests", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/request identity and bounded requester, subject or review-state listing", "resolved requests follow authorization governance retention; subject erasure redacts personal references"),
	owned("_identity_roles", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/role identity and exact role-key lookup", "role deletion is rejected or cascaded only after active assignments and menu links are removed"),
	owned("_identity_user_role_assignments", schemaownership.RetentionUserErase, []string{"workspace_id", "id"}, "workspace/assignment identity and bounded user or role lookup", "revocation preserves bounded terminal state; user erasure removes subject-owned assignments"),
	owned("_identity_users", schemaownership.RetentionUserErase, []string{"workspace_id", "id"}, "workspace/user identity, globally unique login resolution and bounded organization hierarchy lookup", "subject erasure anonymizes the user aggregate after credentials and active sessions are removed"),
	owned("_identity_workflow_workload_bindings", schemaownership.RetentionProduct, []string{"workspace_id", "id"}, "workspace/application/workflow identity and bounded release-state lookup", "release replacement deactivates obsolete bindings; application removal deletes terminal bindings"),
}

func owned(name string, retention schemaownership.RetentionClass, primaryKey []string, queryPath, deletionPolicy string) schemaownership.Table {
	return schemaownership.Table{
		Name: name, Owner: MigrationOwner, WorkspaceScope: schemaownership.ScopeWorkspace,
		RetentionClass: retention, PrimaryKey: primaryKey, BoundedQueryPath: queryPath, DeletionPolicy: deletionPolicy,
	}
}

func SchemaOwnership() []schemaownership.Table {
	return schemaownership.Clone(schemaTableOwnership)
}

func OwnedTables() []string {
	return schemaownership.Names(SchemaOwnership())
}

func IdentityTableOwnership() []TableOwnership {
	result := append([]TableOwnership(nil), identityTableOwnership...)
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}
