package schema

import "sort"

type TableBoundary string

const (
	TableBoundarySchemaControl  TableBoundary = "schema_control"
	TableBoundaryDirectory      TableBoundary = "identity_directory"
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
	{Name: "_domainry_managed_identity_database", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationExcluded},
	{Name: "_schema_migrations", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationExcluded},
	{Name: "_identity_rls_policies", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationExcluded},
	{Name: "_schema_materializations", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationExcluded},
	{Name: "action_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "auth_assertion_replays", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "auth_authorization_codes", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "auth_login_transactions", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "auth_mutation_receipts", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded},
	{Name: "auth_otp_delivery_limits", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "auth_provider_credentials", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationKeyReferenceOnly, ContainsSecret: true},
	{Name: "auth_refresh_tokens", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "field_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "identity_access_review_items", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_access_review_receipts", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_access_reviews", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_authoring_receipts", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_authorization_catalog_revisions", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_authorization_catalogs", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_change_plan_drafts", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "identity_change_plan_operations", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_credentials", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "identity_departments", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationPortable},
	{Name: "identity_entitlement_batch_receipts", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_external_accounts", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationPortable},
	{Name: "identity_localized_text", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "identity_menus", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_metadata_refresh_intents", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationExcluded},
	{Name: "identity_mfa_factors", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "identity_profile_binding_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "identity_profile_binding_events", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_profile_binding_receipts", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_profile_bindings", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationPortable},
	{Name: "identity_portability_export_receipts", Boundary: TableBoundaryEvidence, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_portability_import_receipts", Boundary: TableBoundaryEvidence, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_portability_write_fence_events", Boundary: TableBoundaryEvidence, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_role_menu_assignments", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_role_requests", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_roles", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_user_role_assignments", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "identity_users", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationPortable},
	{Name: "identity_workforce_assignments", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationPortable},
	{Name: "identity_workforce_legacy_migration_receipts", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_workforce_profiles", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationPortable},
	{Name: "identity_workforce_transfer_batch_receipts", Boundary: TableBoundaryDirectory, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "identity_workspace_write_fences", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "metadata_catalog", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "metadata_definition_versions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "object_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "role_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "validation_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "view_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
}

func IdentityTableOwnership() []TableOwnership {
	result := append([]TableOwnership(nil), identityTableOwnership...)
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}
