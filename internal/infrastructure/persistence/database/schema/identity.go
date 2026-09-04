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
		"_identity_role_definition_versions": {
			"id " + text + " PRIMARY KEY",
			"resource_type " + text + " NOT NULL",
			"resource_key " + text + " NOT NULL",
			"schema_version " + text + " NOT NULL",
			"schema_hash " + text + " NOT NULL",
			"payload_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"_identity_role_definitions": {
			"id " + text + " PRIMARY KEY",
			"resource_key " + text + " NOT NULL",
			"object_key " + text + " NOT NULL",
			"name TEXT NOT NULL",
			"payload_json TEXT NOT NULL",
			"schema_version " + text + " NOT NULL",
			"schema_hash " + text + " NOT NULL",
			"source_kind " + text + " NOT NULL",
			"source_id " + text + " NOT NULL",
			"disabled_at " + text,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_profile_binding_definition_versions": {
			"id " + text + " PRIMARY KEY",
			"resource_type " + text + " NOT NULL",
			"resource_key " + text + " NOT NULL",
			"schema_version " + text + " NOT NULL",
			"schema_hash " + text + " NOT NULL",
			"payload_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"_identity_profile_binding_definitions": {
			"id " + text + " PRIMARY KEY",
			"resource_key " + text + " NOT NULL",
			"object_key " + text + " NOT NULL",
			"name TEXT NOT NULL",
			"payload_json TEXT NOT NULL",
			"schema_version " + text + " NOT NULL",
			"schema_hash " + text + " NOT NULL",
			"source_kind " + text + " NOT NULL",
			"source_id " + text + " NOT NULL",
			"disabled_at " + text,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_organization_units": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"code " + text + " NOT NULL",
			"name TEXT NOT NULL",
			"node_type " + text + " NOT NULL",
			"parent_id " + text,
			"path TEXT NOT NULL",
			"ancestor_ids TEXT NOT NULL",
			"depth INTEGER NOT NULL",
			"sort_order INTEGER NOT NULL DEFAULT 0",
			"status " + text + " NOT NULL DEFAULT 'active'",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_users": {
			"id " + text + " PRIMARY KEY",
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
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_roles": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"role_key " + text + " NOT NULL",
			"label TEXT NOT NULL",
			"description TEXT",
			"status " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_role_requests": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"requested_by " + text,
			"provider " + text,
			"provider_subject " + text,
			"role_ids_json TEXT NOT NULL",
			"status " + text + " NOT NULL",
			"reason TEXT",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
			"reviewed_by " + text,
			"reviewed_at " + text,
			"review_note TEXT",
		},
		"_identity_user_role_assignments": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"binding_key " + text,
			"profile_id " + text,
			"source " + text + " NOT NULL DEFAULT 'manual'",
			"status " + text + " NOT NULL DEFAULT 'active'",
			"valid_from " + text,
			"valid_until " + text,
			"granted_by " + text,
			"grant_reason TEXT",
			"revoked_by " + text,
			"revoked_at " + text,
			"revoke_reason TEXT",
			"expires_at " + text,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_authoring_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"use_case " + text + " NOT NULL",
			"resource_type " + text + " NOT NULL",
			"target_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"status " + text + " NOT NULL",
			"result_json TEXT NOT NULL DEFAULT '{}'",
			"lease_owner " + text + " NOT NULL",
			"lease_expires_at " + text + " NOT NULL",
			"fencing_token BIGINT NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_workspace_write_fences": {
			"workspace_id " + text + " PRIMARY KEY",
			"state " + text + " NOT NULL",
			"evidence_sha256 " + text + " NOT NULL",
			"frozen_by " + text + " NOT NULL",
			"frozen_at " + text + " NOT NULL",
			"released_by " + text + " NOT NULL DEFAULT ''",
			"released_at " + text,
			"updated_at " + text + " NOT NULL",
		},
		"_identity_entitlement_batch_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"actor_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"result_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"_identity_access_reviews": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"period_start " + text + " NOT NULL",
			"period_end " + text + " NOT NULL",
			"due_at " + text + " NOT NULL",
			"status " + text + " NOT NULL",
			"created_by " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_access_review_items": {
			"id " + text + " PRIMARY KEY",
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
			"last_used_at " + text,
			"status " + text + " NOT NULL",
			"decision " + text,
			"replacement_role_id " + text,
			"expires_at " + text,
			"reviewer_id " + text,
			"reason TEXT",
			"decided_at " + text,
			"version BIGINT NOT NULL DEFAULT 1",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_access_review_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"item_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"result_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"_identity_menus": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"menu_key " + text + " NOT NULL",
			"label TEXT NOT NULL",
			"description TEXT",
			"route TEXT",
			"icon " + text,
			"parent_id " + text,
			"sort_order INTEGER NOT NULL",
			"status " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_role_menu_assignments": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"menu_id " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_credentials": {
			"user_id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"password_hash TEXT NOT NULL",
			"password_updated_at " + text + " NOT NULL",
			"failed_login_count INTEGER NOT NULL DEFAULT 0",
			"locked_until " + text,
			"last_login_at " + text,
			"must_change_password " + boolType + " NOT NULL DEFAULT " + boolFalse,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_auth_refresh_tokens": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"session_id " + text + " NOT NULL",
			"audience " + text + " NOT NULL DEFAULT ''",
			"token_hash TEXT NOT NULL",
			"expires_at " + text + " NOT NULL",
			"revoked_at " + text,
			"replaced_by_id " + text,
			"last_used_at " + text,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_auth_provider_credentials": {
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"configuration_json TEXT NOT NULL",
			"secret_envelope TEXT NOT NULL",
			"updated_by " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_auth_login_transactions": {
			"state_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"payload_json TEXT NOT NULL",
			"attempts INTEGER NOT NULL DEFAULT 0",
			"expires_at " + text + " NOT NULL",
			"consumed_at " + text,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_auth_otp_delivery_limits": {
			"subject_key_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"next_allowed_at " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_auth_assertion_replays": {
			"replay_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"expires_at " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"_identity_auth_authorization_codes": {
			"code_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"application_key " + text + " NOT NULL",
			"session_json TEXT NOT NULL",
			"redirect_url TEXT NOT NULL",
			"expires_at " + text + " NOT NULL",
			"consumed_at " + text,
			"created_at " + text + " NOT NULL",
		},
		"_identity_auth_mutation_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"use_case " + text + " NOT NULL",
			"target_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"status " + text + " NOT NULL",
			"result_json TEXT NOT NULL",
			"lease_owner " + text + " NOT NULL",
			"lease_expires_at " + text + " NOT NULL",
			"fencing_token BIGINT NOT NULL",
			"error_code " + text + " NOT NULL",
			"expires_at " + text + " NOT NULL",
			"actor_id " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_external_accounts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"provider " + text + " NOT NULL",
			"provider_subject " + text + " NOT NULL",
			"email TEXT",
			"phone TEXT",
			"display_name TEXT",
			"avatar_url TEXT",
			"metadata TEXT",
			"linked_at " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_mfa_factors": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"factor_type " + text + " NOT NULL",
			"label TEXT",
			"provider " + text,
			"provider_ref " + text,
			"status " + text + " NOT NULL",
			"verified_at " + text,
			"last_used_at " + text,
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"_identity_profile_bindings": {
			"id " + identityIndexText + " PRIMARY KEY",
			"workspace_id " + identityIndexText + " NOT NULL",
			"binding_key " + identityIndexText + " NOT NULL",
			"object_key " + identityIndexText + " NOT NULL",
			"profile_id " + identityIndexText + " NOT NULL",
			"identity_user_id " + identityIndexText,
			"status " + identityIndexText + " NOT NULL",
			"invitation_channel " + identityIndexText,
			"claim_proof_type " + identityIndexText,
			"version BIGINT NOT NULL",
			"created_at " + identityIndexText + " NOT NULL",
			"updated_at " + identityIndexText + " NOT NULL",
		},
		"_identity_profile_binding_receipts": {
			"id " + identityIndexText + " PRIMARY KEY",
			"workspace_id " + identityIndexText + " NOT NULL",
			"binding_key " + identityIndexText + " NOT NULL",
			"object_key " + identityIndexText + " NOT NULL",
			"profile_id " + identityIndexText + " NOT NULL",
			"operation " + identityIndexText + " NOT NULL",
			"idempotency_key " + identityIndexText + " NOT NULL",
			"request_fingerprint " + identityIndexText + " NOT NULL",
			"binding_json TEXT NOT NULL",
			"created_at " + identityIndexText + " NOT NULL",
		},
		"_identity_profile_binding_events": {
			"id " + identityIndexText + " PRIMARY KEY",
			"workspace_id " + identityIndexText + " NOT NULL",
			"binding_key " + identityIndexText + " NOT NULL",
			"object_key " + identityIndexText + " NOT NULL",
			"profile_id " + identityIndexText + " NOT NULL",
			"operation " + identityIndexText + " NOT NULL",
			"previous_user_id " + identityIndexText,
			"identity_user_id " + identityIndexText,
			"binding_version BIGINT NOT NULL",
			"idempotency_key " + identityIndexText + " NOT NULL",
			"actor_id " + identityIndexText + " NOT NULL",
			"reason TEXT",
			"approval_id " + identityIndexText,
			"status " + identityIndexText + " NOT NULL",
			"created_at " + identityIndexText + " NOT NULL",
		},
	}
	workspaceIdentities := prepareWorkspaceScopedIdentities(tables)
	// These baseline tables use engine-provided physical types that
	// domainry-orm cannot yet express as a custom ColumnType.
	for _, table := range sortedSchemaTables(tables) {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+quotedColumnDefinitions(s, tables[table])+")"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	if err := s.EnsureCompositePrimaryKey(ctx, "_identity_auth_provider_credentials", "workspace_id", "provider_key"); err != nil {
		return fmt.Errorf("ensure workspace auth provider credential identity: %w", err)
	}
	if err := ensureWorkspaceScopedIdentities(ctx, s, workspaceIdentities); err != nil {
		return err
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_auth_mutation_receipts", "uniq_auth_mutation_receipt_scope", true, "workspace_id", "use_case", "target_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create auth mutation receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_auth_mutation_receipts", "idx_auth_mutation_receipt_lease", false, "status", "lease_expires_at"); err != nil {
		return fmt.Errorf("create auth mutation receipt lease index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_entitlement_batch_receipts", "uniq_identity_entitlement_batch_receipt", true, "workspace_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity entitlement batch receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_authoring_receipts", "uniq_identity_authoring_receipt_key", true, "workspace_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity authoring receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_authoring_receipts", "idx_identity_authoring_receipt_lease", false, "status", "lease_expires_at"); err != nil {
		return fmt.Errorf("create identity authoring receipt lease index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_access_review_items", "uniq_identity_access_review_assignment", true, "workspace_id", "review_id", "user_id", "role_id"); err != nil {
		return fmt.Errorf("create identity access review item unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "_identity_access_review_receipts", "uniq_identity_access_review_receipt", true, "workspace_id", "item_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity access review receipt unique index: %w", err)
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
		{table: "_identity_menus", name: "idx_identity_menus_parent", columns: []string{"workspace_id", "parent_id"}},
		{table: "_identity_role_menu_assignments", name: "idx_identity_role_menus_role", columns: []string{"workspace_id", "role_id"}},
		{table: "_identity_role_menu_assignments", name: "idx_identity_role_menus_menu", columns: []string{"workspace_id", "menu_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_replaced_by", columns: []string{"workspace_id", "replaced_by_id"}},
		{table: "_identity_external_accounts", name: "idx_identity_external_accounts_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_mfa_factors", name: "idx_identity_mfa_factors_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_profile_bindings", name: "idx_identity_profile_bindings_user", columns: []string{"workspace_id", "binding_key", "identity_user_id"}},
		{table: "_identity_profile_binding_events", name: "idx_identity_profile_binding_events_profile", columns: []string{"workspace_id", "object_key", "profile_id", "created_at"}},
		{table: "_identity_profile_binding_events", name: "idx_identity_profile_binding_events_status", columns: []string{"status", "created_at"}},
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
		{table: "_identity_role_definitions", name: "uniq_identity_role_definition_key", columns: []string{"resource_key"}},
		{table: "_identity_role_definition_versions", name: "uniq_identity_role_definition_version", columns: []string{"resource_type", "resource_key", "schema_version", "schema_hash"}},
		{table: "_identity_profile_binding_definitions", name: "uniq_identity_profile_binding_definition_key", columns: []string{"resource_key"}},
		{table: "_identity_profile_binding_definition_versions", name: "uniq_identity_profile_binding_definition_version", columns: []string{"resource_type", "resource_key", "schema_version", "schema_hash"}},
		{table: "_identity_organization_units", name: "uniq_identity_organization_unit_code", columns: []string{"workspace_id", "code"}},
		{table: "_identity_profile_bindings", name: "uniq_identity_profile_binding_profile", columns: []string{"workspace_id", "object_key", "profile_id"}},
		{table: "_identity_profile_bindings", name: "uniq_identity_profile_binding_user", columns: []string{"workspace_id", "binding_key", "identity_user_id"}},
		{table: "_identity_profile_binding_receipts", name: "uniq_identity_profile_binding_receipt", columns: []string{"workspace_id", "object_key", "profile_id", "operation", "idempotency_key"}},
		{table: "_identity_profile_binding_events", name: "uniq_identity_profile_binding_event", columns: []string{"workspace_id", "object_key", "profile_id", "operation", "idempotency_key"}},
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
