package portability

type datasetSpec struct {
	name      string
	table     string
	columns   []string
	orderBy   []string
	workspace string
}

var portableDatasetSpecs = []datasetSpec{
	{
		name: "authorization_catalog_revisions", table: "identity_authorization_catalog_revisions", workspace: "workspace_id", orderBy: []string{"application_key", "revision", "id"},
		columns: []string{"id", "workspace_id", "application_key", "catalog_json", "revision", "sha256", "published_at", "created_at"},
	},
	{
		name: "authorization_catalogs", table: "identity_authorization_catalogs", workspace: "workspace_id", orderBy: []string{"application_key"},
		columns: []string{"application_key", "workspace_id", "catalog_json", "revision", "sha256", "published_at", "updated_at"},
	},
	{
		name: "departments", table: "identity_departments", workspace: "workspace_id", orderBy: []string{"path", "id"},
		columns: []string{"id", "workspace_id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at"},
	},
	{
		name: "external_accounts", table: "identity_external_accounts", workspace: "workspace_id", orderBy: []string{"provider", "provider_subject", "id"},
		columns: []string{"id", "workspace_id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at", "created_at", "updated_at"},
	},
	{
		name: "menus", table: "identity_menus", workspace: "workspace_id", orderBy: []string{"sort_order", "menu_key", "id"},
		columns: []string{"id", "workspace_id", "menu_key", "label", "description", "route", "icon", "parent_id", "sort_order", "status", "created_at", "updated_at"},
	},
	{
		name: "profile_bindings", table: "identity_profile_bindings", workspace: "workspace_id", orderBy: []string{"binding_key", "object_key", "profile_id", "id"},
		columns: []string{"id", "workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at"},
	},
	{
		name: "role_menu_assignments", table: "identity_role_menu_assignments", workspace: "workspace_id", orderBy: []string{"role_id", "menu_id", "id"},
		columns: []string{"id", "workspace_id", "role_id", "menu_id", "created_at", "updated_at"},
	},
	{
		name: "roles", table: "identity_roles", workspace: "workspace_id", orderBy: []string{"role_key", "id"},
		columns: []string{"id", "workspace_id", "role_key", "label", "description", "status", "created_at", "updated_at"},
	},
	{
		name: "user_role_assignments", table: "identity_user_role_assignments", workspace: "workspace_id", orderBy: []string{"user_id", "role_id", "id"},
		columns: []string{"id", "workspace_id", "user_id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason", "expires_at", "created_at", "updated_at"},
	},
	{
		name: "users", table: "identity_users", workspace: "workspace_id", orderBy: []string{"id"},
		columns: []string{"id", "workspace_id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status", "version", "created_at", "updated_at"},
	},
	{
		name: "workforce_assignments", table: "identity_workforce_assignments", workspace: "workspace_id", orderBy: []string{"workforce_profile_id", "id"},
		columns: []string{"id", "workspace_id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "created_at", "updated_at"},
	},
	{
		name: "workforce_profiles", table: "identity_workforce_profiles", workspace: "workspace_id", orderBy: []string{"identity_user_id", "id"},
		columns: []string{"id", "workspace_id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "created_at", "updated_at"},
	},
}

var excludedWorkspaceTables = map[string]string{
	"authorization_codes": "auth_authorization_codes",
	"credentials":         "identity_credentials",
	"login_transactions":  "auth_login_transactions",
	"mfa_factors":         "identity_mfa_factors",
	"otp_delivery_limits": "auth_otp_delivery_limits",
	"provider_secrets":    "auth_provider_credentials",
	"refresh_sessions":    "auth_refresh_tokens",
	"saml_replay_claims":  "auth_assertion_replays",
}

func datasetSpecNamed(name string) (datasetSpec, bool) {
	for _, spec := range portableDatasetSpecs {
		if spec.name == name {
			return spec, true
		}
	}
	return datasetSpec{}, false
}
