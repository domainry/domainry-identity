package schema

import "sort"

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
	{Name: "_identity_managed_database", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationExcluded},
	{Name: "_identity_auth_assertion_replays", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_authorization_codes", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_login_transactions", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_mutation_receipts", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded},
	{Name: "_identity_auth_otp_delivery_limits", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_auth_provider_credentials", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationKeyReferenceOnly, ContainsSecret: true},
	{Name: "_identity_auth_refresh_tokens", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_access_review_items", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_access_review_receipts", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_access_reviews", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_applications", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationPortable},
	{Name: "_identity_authoring_receipts", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_credentials", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_organization_units", Boundary: TableBoundaryIdentityCore, MigrationDisposition: MigrationPortable},
	{Name: "_identity_profile_binding_definition_versions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "_identity_entitlement_batch_receipts", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_handler_deliveries", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_workspace_bootstrap_receipts", Boundary: TableBoundaryIdentityCore, MigrationDisposition: MigrationPortable},
	{Name: "_identity_installation_administrator_bootstrap_receipts", Boundary: TableBoundaryIdentityCore, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_store_organization_states", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_store_organization_deliveries", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_organization_unit_delivery_states", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_organization_unit_deliveries", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_external_accounts", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationPortable},
	{Name: "_identity_localized_texts", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "_identity_menus", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_permissions", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_metadata_refresh_intents", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationExcluded},
	{Name: "_identity_mfa_factors", Boundary: TableBoundaryAuthentication, MigrationDisposition: MigrationExcluded, ContainsSecret: true},
	{Name: "_identity_profile_binding_events", Boundary: TableBoundaryProfileBinding, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_profile_binding_definitions", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
	{Name: "_identity_profile_binding_receipts", Boundary: TableBoundaryProfileBinding, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_profile_bindings", Boundary: TableBoundaryProfileBinding, MigrationDisposition: MigrationPortable},
	{Name: "_identity_role_menu_assignments", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_role_definition_versions", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_role_definitions", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_role_requests", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_roles", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_user_role_assignments", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_workflow_workload_bindings", Boundary: TableBoundaryAuthorization, MigrationDisposition: MigrationPortable},
	{Name: "_identity_users", Boundary: TableBoundaryIdentityCore, MigrationDisposition: MigrationPortable},
	{Name: "_identity_workspace_write_fences", Boundary: TableBoundarySchemaControl, MigrationDisposition: MigrationEvidenceOnly},
	{Name: "_identity_manifest_catalog", Boundary: TableBoundaryMetadata, MigrationDisposition: MigrationPortable},
}

func IdentityTableOwnership() []TableOwnership {
	result := append([]TableOwnership(nil), identityTableOwnership...)
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}
