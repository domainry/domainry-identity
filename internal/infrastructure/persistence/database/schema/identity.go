package schema

import (
	"context"
	"fmt"
)

func EnsureIdentitySchema(ctx context.Context, s Store) error {
	text := s.MetadataIDColumnType()
	types := s.SchemaTypes()
	boolType, boolFalse := types.Boolean, types.FalseLiteral
	defaultText, identityIndexText := types.DefaultText, types.IndexedText
	tables := map[string][]string{
		"_identity_organization_units": {
			"id " + types.AutoIncrementBigInt,
			"organization_unit_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"code " + text + " NOT NULL",
			"name TEXT NOT NULL",
			"sibling_key " + identityIndexText + " NOT NULL DEFAULT ''",
			"node_type " + text + " NOT NULL",
			"parent_id " + text,
			"path TEXT NOT NULL",
			"ancestor_ids TEXT NOT NULL",
			"depth INTEGER NOT NULL",
			"sort_order INTEGER NOT NULL DEFAULT 0",
			"status " + text + " NOT NULL DEFAULT 'active'",
			"delivery_owner " + identityIndexText + " NOT NULL DEFAULT ''",
			"delivery_version BIGINT NOT NULL DEFAULT 0",
			"delivery_state_fingerprint " + text + " NOT NULL DEFAULT ''",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_users": {
			"id " + types.AutoIncrementBigInt,
			"user_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"name TEXT NOT NULL",
			"given_name TEXT NOT NULL DEFAULT ''",
			"middle_name TEXT NOT NULL DEFAULT ''",
			"family_name TEXT NOT NULL DEFAULT ''",
			"name_prefix TEXT NOT NULL DEFAULT ''",
			"name_suffix TEXT NOT NULL DEFAULT ''",
			"native_name TEXT NOT NULL DEFAULT ''",
			"name_locale " + defaultText + " NOT NULL DEFAULT ''",
			"email TEXT NOT NULL",
			"login_name_key " + text,
			"phone " + defaultText + " NOT NULL DEFAULT ''",
			"account_type " + text + " NOT NULL DEFAULT 'human'",
			"locale " + defaultText + " NOT NULL DEFAULT ''",
			"timezone " + defaultText + " NOT NULL DEFAULT ''",
			"org_id " + text,
			"support_org_id " + text,
			"manager_user_id " + text,
			"reporting_path TEXT NOT NULL DEFAULT ''",
			"worker_no " + defaultText + " NOT NULL DEFAULT ''",
			"worker_type " + defaultText + " NOT NULL DEFAULT ''",
			"work_status " + defaultText + " NOT NULL DEFAULT ''",
			"start_date " + text,
			"end_date " + text,
			"status " + text + " NOT NULL",
			"version BIGINT NOT NULL DEFAULT 1",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_roles": {
			"id " + types.AutoIncrementBigInt,
			"role_id " + text + " NOT NULL",
			"workspace_id " + text,
			"scope_type " + text + " NOT NULL",
			"source_owner " + text + " NOT NULL",
			"role_key " + text + " NOT NULL",
			"label TEXT NOT NULL",
			"description TEXT",
			"definition_json TEXT NOT NULL",
			"status " + text + " NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_role_requests": {
			"id " + types.AutoIncrementBigInt,
			"role_request_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"requested_by " + text,
			"provider " + text,
			"provider_subject " + text,
			"role_ids_json TEXT NOT NULL",
			"status " + text + " NOT NULL",
			"reason TEXT",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
			"reviewed_by " + text,
			"reviewed_at BIGINT NOT NULL DEFAULT 0",
			"review_note TEXT",
		},
		"_identity_user_role_assignments": {
			"id " + types.AutoIncrementBigInt,
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"binding_key " + text,
			"profile_id " + text,
			"source " + text + " NOT NULL DEFAULT 'manual'",
			"status " + text + " NOT NULL DEFAULT 'active'",
			"valid_from BIGINT NOT NULL DEFAULT 0",
			"valid_until BIGINT NOT NULL DEFAULT 0",
			"granted_by " + text,
			"grant_reason TEXT",
			"revoked_by " + text,
			"revoked_at BIGINT NOT NULL DEFAULT 0",
			"revoke_reason TEXT",
			"expires_at BIGINT NOT NULL DEFAULT 0",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_workflow_workload_bindings": {
			"id " + types.AutoIncrementBigInt,
			"workspace_id " + text + " NOT NULL",
			"application_key " + text + " NOT NULL",
			"subject_id " + text + " NOT NULL",
			"workflow_key " + text + " NOT NULL",
			"definition_version_id " + text + " NOT NULL",
			"definition_version INTEGER NOT NULL",
			"role_key " + text + " NOT NULL",
			"action_keys_json TEXT NOT NULL",
			"release_id " + text + " NOT NULL",
			"release_digest " + text + " NOT NULL",
			"source_kind " + text + " NOT NULL",
			"source_id " + text + " NOT NULL",
			"status " + text + " NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
			"deactivated_at BIGINT NOT NULL DEFAULT 0",
		},
		"_identity_access_reviews": {
			"id " + types.AutoIncrementBigInt,
			"review_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"period_start BIGINT NOT NULL",
			"period_end BIGINT NOT NULL",
			"due_at BIGINT NOT NULL",
			"status " + text + " NOT NULL",
			"created_by " + text + " NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_access_review_items": {
			"id " + types.AutoIncrementBigInt,
			"review_item_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"review_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"role_key " + text + " NOT NULL",
			"binding_key " + text,
			"profile_id " + text,
			"risk_level " + text + " NOT NULL",
			"priority " + text + " NOT NULL",
			"priority_reasons_json TEXT NOT NULL DEFAULT '[]'",
			"last_used_at BIGINT NOT NULL DEFAULT 0",
			"status " + text + " NOT NULL",
			"decision " + text,
			"replacement_role_id " + text,
			"expires_at BIGINT NOT NULL DEFAULT 0",
			"reviewer_id " + text,
			"reason TEXT",
			"decided_at BIGINT NOT NULL DEFAULT 0",
			"version BIGINT NOT NULL DEFAULT 1",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_menus": {
			"id " + types.AutoIncrementBigInt,
			"menu_id " + text + " NOT NULL",
			"source_owner " + text + " NOT NULL",
			"menu_key " + text + " NOT NULL",
			"label TEXT NOT NULL",
			"description TEXT",
			"route TEXT",
			"icon " + text,
			"parent_id " + text,
			"sort_order INTEGER NOT NULL",
			"status " + text + " NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_role_menu_assignments": {
			"id " + types.AutoIncrementBigInt,
			"role_id " + text + " NOT NULL",
			"menu_id " + text + " NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_credentials": {
			"id " + types.AutoIncrementBigInt,
			"user_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"password_hash TEXT NOT NULL",
			"password_updated_at BIGINT NOT NULL",
			"failed_login_count INTEGER NOT NULL DEFAULT 0",
			"locked_until BIGINT NOT NULL DEFAULT 0",
			"last_login_at BIGINT NOT NULL DEFAULT 0",
			"must_change_password " + boolType + " NOT NULL DEFAULT " + boolFalse,
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_auth_refresh_tokens": {
			"id " + types.AutoIncrementBigInt,
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"session_id " + text + " NOT NULL",
			"audience " + text + " NOT NULL DEFAULT ''",
			"authentication_time BIGINT NOT NULL DEFAULT 0",
			"authentication_methods TEXT NOT NULL DEFAULT '[]'",
			"assurance_level " + text + " NOT NULL DEFAULT ''",
			"token_hash " + identityIndexText + " NOT NULL",
			"expires_at BIGINT NOT NULL",
			"revoked_at BIGINT NOT NULL DEFAULT 0",
			"replaced_by_hash " + identityIndexText,
			"last_used_at BIGINT NOT NULL DEFAULT 0",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_auth_provider_credentials": {
			"id " + types.AutoIncrementBigInt,
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"configuration_json TEXT NOT NULL",
			"secret_envelope TEXT NOT NULL",
			"updated_by " + text + " NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_auth_login_transactions": {
			"id " + types.AutoIncrementBigInt,
			"state_hash " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"subject_key_hash " + text,
			"challenge_status " + text + " NOT NULL DEFAULT 'active'",
			"challenge_purpose " + text + " NOT NULL DEFAULT 'login'",
			"delivery_ref " + text,
			"delivery_error " + text,
			"payload_json TEXT NOT NULL",
			"attempts INTEGER NOT NULL DEFAULT 0",
			"expires_at BIGINT NOT NULL",
			"consumed_at BIGINT NOT NULL DEFAULT 0",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_auth_otp_delivery_limits": {
			"id " + types.AutoIncrementBigInt,
			"subject_key_hash " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"next_allowed_at BIGINT NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_auth_assertion_replays": {
			"id " + types.AutoIncrementBigInt,
			"replay_hash " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"expires_at BIGINT NOT NULL",
			"created_at BIGINT NOT NULL",
		},
		"_identity_auth_authorization_codes": {
			"id " + types.AutoIncrementBigInt,
			"code_hash " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"application_key " + text + " NOT NULL",
			"session_json TEXT NOT NULL",
			"redirect_url TEXT NOT NULL",
			"code_challenge TEXT NOT NULL DEFAULT ''",
			"code_challenge_method " + text + " NOT NULL DEFAULT ''",
			"expires_at BIGINT NOT NULL",
			"consumed_at BIGINT NOT NULL DEFAULT 0",
			"created_at BIGINT NOT NULL",
		},
		"_identity_external_accounts": {
			"id " + types.AutoIncrementBigInt,
			"external_account_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"provider " + text + " NOT NULL",
			"provider_subject " + text + " NOT NULL",
			"email TEXT",
			"phone TEXT",
			"display_name TEXT",
			"avatar_url TEXT",
			"metadata TEXT",
			"linked_at BIGINT NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_mfa_factors": {
			"id " + types.AutoIncrementBigInt,
			"mfa_factor_id " + text + " NOT NULL",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"factor_type " + text + " NOT NULL",
			"label TEXT",
			"provider " + text,
			"provider_ref " + text,
			"status " + text + " NOT NULL",
			"verified_at BIGINT NOT NULL DEFAULT 0",
			"last_used_at BIGINT NOT NULL DEFAULT 0",
			"totp_secret TEXT",
			"totp_step BIGINT NOT NULL DEFAULT -1",
			"totp_failures INTEGER NOT NULL DEFAULT 0",
			"totp_locked_until BIGINT NOT NULL DEFAULT 0",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
		"_identity_profile_bindings": {
			"id " + types.AutoIncrementBigInt,
			"workspace_id " + identityIndexText + " NOT NULL",
			"binding_key " + identityIndexText + " NOT NULL",
			"object_key " + identityIndexText + " NOT NULL",
			"profile_id " + identityIndexText + " NOT NULL",
			"identity_user_id " + identityIndexText,
			"status " + identityIndexText + " NOT NULL",
			"invitation_channel " + identityIndexText,
			"claim_proof_type " + identityIndexText,
			"version BIGINT NOT NULL",
			"created_at BIGINT NOT NULL",
			"updated_at BIGINT NOT NULL",
		},
	}
	// These final-schema tables use engine-provided physical types that
	// domainry-orm cannot yet express as a custom ColumnType. Every definition
	// carries its own dialect-specific auto-increment id primary key.
	for _, table := range sortedSchemaTables(tables) {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+tableColumnDefinitions(s, table, tables[table])+")"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	if err := ensureIdentityGlobalLoginNames(ctx, s); err != nil {
		return err
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_organization_units", "idx_identity_organization_unit_type_page", false, "workspace_id", "node_type", "id"); err != nil {
		return fmt.Errorf("create Identity organization unit type page index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_users", "idx_identity_users_workspace_usage", false, "workspace_id", "account_type", "status"); err != nil {
		return fmt.Errorf("create Identity Workspace usage index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_users", "idx_identity_users_workspace_active_role_usage", false, "workspace_id", "account_type", "status", "id"); err != nil {
		return fmt.Errorf("create active human Identity Workspace role usage user index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_user_role_assignments", "idx_identity_user_roles_workspace_active_usage", false, "workspace_id", "status", "user_id"); err != nil {
		return fmt.Errorf("create active human Identity Workspace role usage assignment index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_workflow_workload_bindings", "idx_identity_workflow_workload_release", false, "workspace_id", "application_key", "release_digest", "status"); err != nil {
		return fmt.Errorf("create Identity workflow workload release index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_access_review_items", "uniq_identity_access_review_assignment", true, "workspace_id", "review_id", "user_id", "role_id"); err != nil {
		return fmt.Errorf("create identity access review item unique index: %w", err)
	}
	for _, index := range []struct {
		table   string
		name    string
		columns []string
	}{
		{table: "_identity_organization_units", name: "idx_identity_organization_units_parent", columns: []string{"workspace_id", "parent_id"}},
		{table: "_identity_users", name: "idx_identity_users_organization_unit", columns: []string{"workspace_id", "org_id"}},
		{table: "_identity_users", name: "idx_identity_users_support_organization_unit", columns: []string{"workspace_id", "support_org_id"}},
		{table: "_identity_users", name: "idx_identity_users_manager", columns: []string{"workspace_id", "manager_user_id"}},
		{table: "_identity_users", name: "idx_identity_users_reporting_path", columns: []string{"workspace_id", "reporting_path"}},
		{table: "_identity_user_role_assignments", name: "idx_identity_user_roles_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_user_role_assignments", name: "idx_identity_user_roles_role", columns: []string{"workspace_id", "role_id"}},
		{table: "_identity_roles", name: "idx_identity_roles_scope", columns: []string{"scope_type", "workspace_id", "role_key"}},
		{table: "_identity_menus", name: "idx_identity_menus_parent", columns: []string{"parent_id"}},
		{table: "_identity_role_menu_assignments", name: "idx_identity_role_menus_role", columns: []string{"role_id"}},
		{table: "_identity_role_menu_assignments", name: "idx_identity_role_menus_menu", columns: []string{"menu_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_hash", columns: []string{"token_hash", "workspace_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_replaced_by", columns: []string{"workspace_id", "replaced_by_hash"}},
		{table: "_identity_auth_login_transactions", name: "idx_auth_login_transactions_state", columns: []string{"state_hash", "provider_key", "workspace_id"}},
		{table: "_identity_auth_login_transactions", name: "idx_auth_login_transactions_subject", columns: []string{"workspace_id", "provider_key", "subject_key_hash", "challenge_status"}},
		{table: "_identity_auth_assertion_replays", name: "idx_auth_assertion_replays_expiry", columns: []string{"workspace_id", "expires_at"}},
		{table: "_identity_external_accounts", name: "idx_identity_external_accounts_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_mfa_factors", name: "idx_identity_mfa_factors_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_profile_bindings", name: "idx_identity_profile_bindings_user", columns: []string{"workspace_id", "binding_key", "identity_user_id"}},
	} {
		if err := s.CreateIndexIfMissing(ctx, index.table, index.name, false, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	for _, index := range []struct {
		table   string
		name    string
		columns []string
	}{
		{table: "_identity_organization_units", name: "uniq_identity_organization_unit_code", columns: []string{"workspace_id", "code"}},
		{table: "_identity_organization_units", name: "uniq_identity_organization_unit_id", columns: []string{"organization_unit_id"}},
		{table: "_identity_users", name: "uniq_identity_user_id", columns: []string{"user_id"}},
		{table: "_identity_roles", name: "uniq_identity_role_id", columns: []string{"role_id"}},
		{table: "_identity_roles", name: "uniq_identity_tenant_role_key", columns: []string{"workspace_id", "role_key"}},
		{table: "_identity_role_requests", name: "uniq_identity_role_request_id", columns: []string{"role_request_id"}},
		{table: "_identity_access_reviews", name: "uniq_identity_access_review_id", columns: []string{"review_id"}},
		{table: "_identity_access_review_items", name: "uniq_identity_access_review_item_id", columns: []string{"review_item_id"}},
		{table: "_identity_menus", name: "uniq_identity_menu_id", columns: []string{"menu_id"}},
		{table: "_identity_menus", name: "uniq_identity_menu_key", columns: []string{"menu_key"}},
		{table: "_identity_external_accounts", name: "uniq_identity_external_account_id", columns: []string{"external_account_id"}},
		{table: "_identity_mfa_factors", name: "uniq_identity_mfa_factor_id", columns: []string{"mfa_factor_id"}},
		{table: "_identity_mfa_factors", name: "uniq_identity_mfa_user_provider", columns: []string{"workspace_id", "user_id", "factor_type", "provider"}},
		{table: "_identity_user_role_assignments", name: "uniq_identity_user_role_assignment", columns: []string{"workspace_id", "user_id", "role_id"}},
		{table: "_identity_workflow_workload_bindings", name: "uniq_identity_workflow_workload", columns: []string{"workspace_id", "application_key", "workflow_key"}},
		{table: "_identity_role_menu_assignments", name: "uniq_identity_role_menu_assignment", columns: []string{"role_id", "menu_id"}},
		{table: "_identity_credentials", name: "uniq_identity_credential_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_auth_refresh_tokens", name: "uniq_identity_auth_refresh_token", columns: []string{"workspace_id", "token_hash"}},
		{table: "_identity_auth_provider_credentials", name: "uniq_identity_auth_provider_credential", columns: []string{"workspace_id", "provider_key"}},
		{table: "_identity_auth_login_transactions", name: "uniq_identity_auth_login_transaction", columns: []string{"workspace_id", "state_hash"}},
		{table: "_identity_auth_otp_delivery_limits", name: "uniq_identity_auth_otp_delivery_limit", columns: []string{"workspace_id", "subject_key_hash"}},
		{table: "_identity_auth_assertion_replays", name: "uniq_identity_auth_assertion_replay", columns: []string{"workspace_id", "replay_hash"}},
		{table: "_identity_auth_authorization_codes", name: "uniq_identity_auth_authorization_code", columns: []string{"workspace_id", "code_hash"}},
		{table: "_identity_organization_units", name: "uniq_identity_organization_unit_sibling_name", columns: []string{"workspace_id", "sibling_key"}},
		{table: "_identity_profile_bindings", name: "uniq_identity_profile_binding_profile", columns: []string{"workspace_id", "object_key", "profile_id"}},
		{table: "_identity_profile_bindings", name: "uniq_identity_profile_binding_user", columns: []string{"workspace_id", "binding_key", "identity_user_id"}},
	} {
		if err := s.CreateIndexIfMissing(ctx, index.table, index.name, true, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	if err := ensureIdentityPermissionsSchema(ctx, s); err != nil {
		return err
	}
	if err := ensureIdentityApplicationsSchema(ctx, s); err != nil {
		return err
	}
	return nil
}
