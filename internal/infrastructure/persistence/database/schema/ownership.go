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
	entity("_identity_access_review_items", schemaownership.RetentionProduct, "review_item_id", "revitem", "workspace/review item identity and bounded review or governed-user listing", "review deletion removes its items; subject erasure redacts governed-user references through Identity lifecycle"),
	entity("_identity_access_reviews", schemaownership.RetentionProduct, "review_id", "review", "workspace/review identity and bounded status/due-date listing", "completed reviews follow Identity governance retention; explicit review deletion removes the aggregate and items"),
	entity("_identity_applications", schemaownership.RetentionProduct, "application_id", "idapp", "workspace/application identity and exact application-key lookup", "application removal deletes the registration after dependent authorization state is revoked"),
	owned("_identity_auth_assertion_replays", schemaownership.KindIdempotency, schemaownership.RetentionTechnicalTTL, []string{"id"}, "workspace/assertion hash identity and bounded expiry cleanup", "expired assertion claims are physically purged after the replay-defense window"),
	owned("_identity_auth_authorization_codes", schemaownership.KindState, schemaownership.RetentionTechnicalTTL, []string{"id"}, "workspace/code hash identity with atomic one-time consume", "consumed and expired authorization codes are physically purged after the protocol replay window"),
	owned("_identity_auth_login_transactions", schemaownership.KindState, schemaownership.RetentionTechnicalTTL, []string{"id"}, "global state-hash resolution followed by workspace/provider consume and bounded subject challenge lookup", "consumed and expired login transactions are physically purged after the authentication window"),
	owned("_identity_auth_otp_delivery_limits", schemaownership.KindState, schemaownership.RetentionTechnicalTTL, []string{"id"}, "workspace/provider/subject delivery throttle identity", "expired delivery throttle rows are physically purged after their rate-limit window"),
	owned("_identity_auth_provider_credentials", schemaownership.KindState, schemaownership.RetentionInstallation, []string{"id"}, "exact workspace/provider configuration identity", "provider removal physically deletes encrypted configuration after active authentication flows are fenced"),
	owned("_identity_auth_refresh_tokens", schemaownership.KindState, schemaownership.RetentionTechnicalTTL, []string{"id"}, "workspace/token hash identity, session lookup and replacement-chain lookup", "logout and reuse revoke the chain; expired terminal tokens are physically purged"),
	owned("_identity_credentials", schemaownership.KindState, schemaownership.RetentionUserErase, []string{"id"}, "exact workspace/user credential identity", "user erasure physically removes the password hash and lockout state"),
	entity("_identity_external_accounts", schemaownership.RetentionUserErase, "external_account_id", "extacct", "workspace/external-account identity and provider-subject or user lookup", "unlinking or user erasure physically removes the external identity mapping"),
	entity("_identity_menus", schemaownership.RetentionProduct, "menu_id", "menu", "workspace/menu identity, menu-key lookup and bounded hierarchy listing", "menu deletion removes assignments before removing the menu row"),
	entity("_identity_mfa_factors", schemaownership.RetentionUserErase, "mfa_factor_id", "mfa", "workspace/factor identity and bounded user-factor lookup", "factor removal or user erasure physically removes factor secret and replay state"),
	entity("_identity_organization_units", schemaownership.RetentionProduct, "organization_unit_id", "orgunit", "workspace/unit identity, code identity and bounded hierarchy traversal", "organization-unit deletion is rejected while governed users or children remain"),
	owned("_identity_permissions", schemaownership.KindState, schemaownership.RetentionProduct, []string{"id"}, "workspace/permission-key identity and bounded source-owner or definition-state listing", "definition reconciliation disables or removes permissions after role references are reconciled"),
	owned("_identity_profile_bindings", schemaownership.KindRelation, schemaownership.RetentionUserErase, []string{"id"}, "workspace/profile identity and exact profile or user binding lookup", "profile unlinking or subject erasure removes the binding after Audit history is recorded"),
	owned("_identity_role_menu_assignments", schemaownership.KindRelation, schemaownership.RetentionProduct, []string{"id"}, "workspace role/menu relation and bounded role-to-menu or menu-to-role lookup", "role or menu deletion physically removes dependent assignments"),
	entity("_identity_role_requests", schemaownership.RetentionProduct, "role_request_id", "rolereq", "workspace/request identity and bounded requester, subject or review-state listing", "resolved requests follow authorization governance retention; subject erasure redacts personal references"),
	entity("_identity_roles", schemaownership.RetentionProduct, "role_id", "role", "workspace/role identity and exact role-key lookup", "role deletion is rejected or cascaded only after active assignments and menu links are removed"),
	owned("_identity_user_role_assignments", schemaownership.KindRelation, schemaownership.RetentionUserErase, []string{"id"}, "workspace user/role relation and bounded user or role lookup", "revocation preserves bounded terminal state; user erasure removes subject-owned assignments"),
	entity("_identity_users", schemaownership.RetentionUserErase, "user_id", "user", "workspace/user identity, globally unique login resolution and bounded organization hierarchy lookup", "subject erasure anonymizes the user aggregate after credentials and active sessions are removed"),
	owned("_identity_workflow_workload_bindings", schemaownership.KindRelation, schemaownership.RetentionProduct, []string{"id"}, "workspace application/workflow relation and bounded release-state lookup", "release replacement deactivates obsolete bindings; application removal deletes terminal bindings"),
}

func owned(name string, kind schemaownership.TableKind, retention schemaownership.RetentionClass, primaryKey []string, queryPath, deletionPolicy string) schemaownership.Table {
	return schemaownership.Table{
		Name: name, Owner: MigrationOwner, Kind: kind, WorkspaceScope: schemaownership.ScopeWorkspace,
		RetentionClass: retention, PrimaryKey: primaryKey, BoundedQueryPath: queryPath, DeletionPolicy: deletionPolicy,
	}
}

func entity(name string, retention schemaownership.RetentionClass, idColumn, prefix, queryPath, deletionPolicy string) schemaownership.Table {
	table := owned(name, schemaownership.KindEntity, retention, []string{"id"}, queryPath, deletionPolicy)
	table.EntityIDColumn = idColumn
	table.EntityIDPrefix = prefix
	table.BusinessKey = []string{idColumn}
	return table
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
