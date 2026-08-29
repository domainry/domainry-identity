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
		"identity_departments": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"name TEXT NOT NULL",
			"parent_id " + text,
			"leader_workforce_profile_id " + text,
			"path TEXT NOT NULL",
			"ancestor_ids TEXT NOT NULL",
			"depth INTEGER NOT NULL",
			"sort_order INTEGER NOT NULL DEFAULT 0",
			"status " + text + " NOT NULL DEFAULT 'active'",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_users": {
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
			"status " + text + " NOT NULL",
			"version BIGINT NOT NULL DEFAULT 1",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_workforce_legacy_migration_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"identity_user_id " + text + " NOT NULL",
			"workforce_profile_id " + text + " NOT NULL",
			"workforce_assignment_id " + text,
			"legacy_facts_json TEXT NOT NULL",
			"migrated_at " + text + " NOT NULL",
		},
		"identity_workforce_profiles": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"organization_id " + text + " NOT NULL",
			"identity_user_id " + text + " NOT NULL",
			"worker_no " + text + " NOT NULL",
			"worker_type " + text + " NOT NULL",
			"work_status " + text + " NOT NULL",
			"start_date " + text,
			"end_date " + text,
			"primary_assignment_id " + text,
			"version BIGINT NOT NULL DEFAULT 1",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_workforce_assignments": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"workforce_profile_id " + text + " NOT NULL",
			"organization_unit_id " + text + " NOT NULL",
			"position_id " + text,
			"manager_workforce_profile_id " + text,
			"assignment_type " + text + " NOT NULL",
			"effective_from " + text,
			"effective_to " + text,
			"status " + text + " NOT NULL",
			"version BIGINT NOT NULL DEFAULT 1",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_roles": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"role_key " + text + " NOT NULL",
			"label TEXT NOT NULL",
			"description TEXT",
			"status " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_role_requests": {
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
		"identity_user_role_assignments": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"workforce_profile_id " + text,
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
		"identity_authoring_receipts": {
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
		"identity_portability_export_receipts": {
			"export_id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"content_sha256 " + text + " NOT NULL",
			"freeze_evidence_sha256 " + text + " NOT NULL",
			"dataset_counts_json TEXT NOT NULL",
			"source_mode " + text + " NOT NULL",
			"exported_at " + text + " NOT NULL",
		},
		"identity_portability_import_receipts": {
			"receipt_id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"content_sha256 " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"imported_counts_json TEXT NOT NULL",
			"imported_at " + text + " NOT NULL",
		},
		"identity_workspace_write_fences": {
			"workspace_id " + text + " PRIMARY KEY",
			"state " + text + " NOT NULL",
			"evidence_sha256 " + text + " NOT NULL",
			"frozen_by " + text + " NOT NULL",
			"frozen_at " + text + " NOT NULL",
			"released_by " + text + " NOT NULL DEFAULT ''",
			"released_at " + text,
			"updated_at " + text + " NOT NULL",
		},
		"identity_portability_write_fence_events": {
			"event_id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"event " + text + " NOT NULL",
			"evidence_sha256 " + text + " NOT NULL",
			"operator " + text + " NOT NULL",
			"occurred_at " + text + " NOT NULL",
		},
		"identity_entitlement_batch_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"actor_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"result_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"identity_workforce_transfer_batch_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"actor_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"result_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"identity_access_reviews": {
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
		"identity_access_review_items": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"review_id " + text + " NOT NULL",
			"user_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"role_key " + text + " NOT NULL",
			"workforce_profile_id " + text,
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
		"identity_access_review_receipts": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"item_id " + text + " NOT NULL",
			"idempotency_key " + text + " NOT NULL",
			"request_fingerprint " + text + " NOT NULL",
			"result_json TEXT NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"identity_menus": {
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
		"identity_role_menu_assignments": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"role_id " + text + " NOT NULL",
			"menu_id " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_credentials": {
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
		"auth_refresh_tokens": {
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
		"auth_provider_credentials": {
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"configuration_json TEXT NOT NULL",
			"secret_envelope TEXT NOT NULL",
			"updated_by " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"auth_login_transactions": {
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
		"auth_otp_delivery_limits": {
			"subject_key_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"next_allowed_at " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"auth_assertion_replays": {
			"replay_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"provider_key " + text + " NOT NULL",
			"expires_at " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"auth_authorization_codes": {
			"code_hash " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"application_key " + text + " NOT NULL",
			"session_json TEXT NOT NULL",
			"redirect_url TEXT NOT NULL",
			"expires_at " + text + " NOT NULL",
			"consumed_at " + text,
			"created_at " + text + " NOT NULL",
		},
		"identity_authorization_catalogs": {
			"application_key " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"catalog_json TEXT NOT NULL",
			"revision " + text + " NOT NULL",
			"sha256 " + text + " NOT NULL",
			"published_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
		},
		"identity_authorization_catalog_revisions": {
			"id " + text + " PRIMARY KEY",
			"workspace_id " + text + " NOT NULL",
			"application_key " + text + " NOT NULL",
			"catalog_json TEXT NOT NULL",
			"revision " + text + " NOT NULL",
			"sha256 " + text + " NOT NULL",
			"published_at " + text + " NOT NULL",
			"created_at " + text + " NOT NULL",
		},
		"auth_mutation_receipts": {
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
		"identity_external_accounts": {
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
		"identity_mfa_factors": {
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
		"identity_profile_bindings": {
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
		"identity_profile_binding_receipts": {
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
		"identity_profile_binding_events": {
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
	for _, table := range sortedSchemaTables(tables) {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+quotedColumnDefinitions(s, tables[table])+")"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	if err := s.EnsureCompositePrimaryKey(ctx, "auth_provider_credentials", "workspace_id", "provider_key"); err != nil {
		return fmt.Errorf("ensure workspace auth provider credential identity: %w", err)
	}
	if err := ensureWorkspaceScopedIdentities(ctx, s, workspaceIdentities); err != nil {
		return err
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_authorization_catalog_revisions", "uniq_identity_authorization_catalog_revision", true, "workspace_id", "application_key", "revision"); err != nil {
		return fmt.Errorf("create authorization catalog revision identity: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_authorization_catalog_revisions", "idx_identity_authorization_catalog_history", false, "workspace_id", "application_key", "published_at"); err != nil {
		return fmt.Errorf("create authorization catalog history index: %w", err)
	}
	if err := migrateLegacyIdentityUserWorkforceFacts(ctx, s); err != nil {
		return err
	}
	if err := migrateLegacyIdentityMenuAudience(ctx, s); err != nil {
		return err
	}
	if err := prepareIdempotencyReceiptMigrations(ctx, s, idempotencyReceiptMigrationSpec{table: "auth_mutation_receipts", scopeColumns: []string{"use_case", "target_id"}, backfillColumns: []string{"use_case", "target_id"}}); err != nil {
		return err
	}
	if err := s.CreateIndexIfMissing(ctx, "auth_mutation_receipts", "uniq_auth_mutation_receipt_scope", true, "workspace_id", "use_case", "target_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create auth mutation receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "auth_mutation_receipts", "idx_auth_mutation_receipt_lease", false, "status", "lease_expires_at"); err != nil {
		return fmt.Errorf("create auth mutation receipt lease index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_entitlement_batch_receipts", "uniq_identity_entitlement_batch_receipt", true, "workspace_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity entitlement batch receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_authoring_receipts", "uniq_identity_authoring_receipt_key", true, "workspace_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity authoring receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_authoring_receipts", "idx_identity_authoring_receipt_lease", false, "status", "lease_expires_at"); err != nil {
		return fmt.Errorf("create identity authoring receipt lease index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_portability_import_receipts", "uniq_identity_portability_import_idempotency", true, "workspace_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create Identity portability import idempotency index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_portability_export_receipts", "uniq_identity_portability_export_content", true, "workspace_id", "content_sha256"); err != nil {
		return fmt.Errorf("create Identity portability export content index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_workforce_transfer_batch_receipts", "uniq_identity_workforce_transfer_batch_receipt", true, "workspace_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity workforce transfer batch receipt unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_access_review_items", "uniq_identity_access_review_assignment", true, "workspace_id", "review_id", "user_id", "role_id"); err != nil {
		return fmt.Errorf("create identity access review item unique index: %w", err)
	}
	if err := s.CreateIndexIfMissing(ctx, "identity_access_review_receipts", "uniq_identity_access_review_receipt", true, "workspace_id", "item_id", "idempotency_key"); err != nil {
		return fmt.Errorf("create identity access review receipt unique index: %w", err)
	}
	if err := s.EnsureColumn(ctx, "identity_access_review_items", "priority_reasons_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.EnsureColumn(ctx, "identity_access_review_items", "last_used_at", text); err != nil {
		return err
	}
	if err := s.EnsureColumn(ctx, "identity_departments", "sort_order", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.EnsureColumn(ctx, "identity_departments", "leader_workforce_profile_id", text); err != nil {
		return err
	}
	for _, column := range []string{"given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale"} {
		if err := s.EnsureColumn(ctx, "identity_users", column, "TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	for column, definition := range map[string]string{
		"account_type": text + " NOT NULL DEFAULT 'human'",
		"locale":       "TEXT NOT NULL DEFAULT ''",
		"timezone":     "TEXT NOT NULL DEFAULT ''",
		"version":      "BIGINT NOT NULL DEFAULT 1",
	} {
		if err := s.EnsureColumn(ctx, "identity_users", column, definition); err != nil {
			return err
		}
	}
	if err := s.EnsureColumn(ctx, "identity_user_role_assignments", "workforce_profile_id", text); err != nil {
		return err
	}
	if err := s.EnsureColumn(ctx, "identity_role_requests", "requested_by", text); err != nil {
		return err
	}
	for column, definition := range map[string]string{
		"binding_key":   text,
		"profile_id":    text,
		"source":        text + " NOT NULL DEFAULT 'manual'",
		"status":        text + " NOT NULL DEFAULT 'active'",
		"valid_from":    text,
		"valid_until":   text,
		"granted_by":    text,
		"grant_reason":  "TEXT",
		"revoked_by":    text,
		"revoked_at":    text,
		"revoke_reason": "TEXT",
	} {
		if err := s.EnsureColumn(ctx, "identity_user_role_assignments", column, definition); err != nil {
			return err
		}
	}
	if err := s.EnsureColumn(ctx, "identity_profile_binding_events", "approval_id", text); err != nil {
		return err
	}
	if err := s.EnsureColumn(ctx, "auth_refresh_tokens", "audience", text+" NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	for _, index := range []struct {
		table   string
		name    string
		columns []string
	}{
		{table: "identity_departments", name: "idx_identity_departments_parent", columns: []string{"workspace_id", "parent_id"}},
		{table: "identity_workforce_profiles", name: "idx_identity_workforce_profiles_user", columns: []string{"workspace_id", "identity_user_id"}},
		{table: "identity_workforce_assignments", name: "idx_identity_workforce_assignments_profile", columns: []string{"workspace_id", "workforce_profile_id"}},
		{table: "identity_workforce_assignments", name: "idx_identity_workforce_assignments_unit", columns: []string{"workspace_id", "organization_unit_id"}},
		{table: "identity_workforce_assignments", name: "idx_identity_workforce_assignments_manager", columns: []string{"workspace_id", "manager_workforce_profile_id"}},
		{table: "identity_user_role_assignments", name: "idx_identity_user_roles_user", columns: []string{"workspace_id", "user_id"}},
		{table: "identity_user_role_assignments", name: "idx_identity_user_roles_role", columns: []string{"workspace_id", "role_id"}},
		{table: "identity_user_role_assignments", name: "idx_identity_user_roles_workforce", columns: []string{"workspace_id", "workforce_profile_id"}},
		{table: "identity_menus", name: "idx_identity_menus_parent", columns: []string{"workspace_id", "parent_id"}},
		{table: "identity_role_menu_assignments", name: "idx_identity_role_menus_role", columns: []string{"workspace_id", "role_id"}},
		{table: "identity_role_menu_assignments", name: "idx_identity_role_menus_menu", columns: []string{"workspace_id", "menu_id"}},
		{table: "auth_refresh_tokens", name: "idx_auth_refresh_tokens_user", columns: []string{"workspace_id", "user_id"}},
		{table: "auth_refresh_tokens", name: "idx_auth_refresh_tokens_replaced_by", columns: []string{"workspace_id", "replaced_by_id"}},
		{table: "identity_external_accounts", name: "idx_identity_external_accounts_user", columns: []string{"workspace_id", "user_id"}},
		{table: "identity_mfa_factors", name: "idx_identity_mfa_factors_user", columns: []string{"workspace_id", "user_id"}},
		{table: "identity_profile_bindings", name: "idx_identity_profile_bindings_user", columns: []string{"workspace_id", "binding_key", "identity_user_id"}},
		{table: "identity_profile_binding_events", name: "idx_identity_profile_binding_events_profile", columns: []string{"workspace_id", "object_key", "profile_id", "created_at"}},
		{table: "identity_profile_binding_events", name: "idx_identity_profile_binding_events_status", columns: []string{"status", "created_at"}},
		{table: "identity_portability_write_fence_events", name: "idx_identity_portability_write_fence_events_workspace", columns: []string{"workspace_id", "occurred_at"}},
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
		{table: "identity_workforce_profiles", name: "uniq_identity_workforce_profiles_user", columns: []string{"workspace_id", "organization_id", "identity_user_id"}},
		{table: "identity_workforce_profiles", name: "uniq_identity_workforce_profiles_worker_no", columns: []string{"workspace_id", "organization_id", "worker_no"}},
		{table: "identity_workforce_legacy_migration_receipts", name: "uniq_identity_workforce_legacy_migration_user", columns: []string{"workspace_id", "identity_user_id"}},
		{table: "identity_profile_bindings", name: "uniq_identity_profile_binding_profile", columns: []string{"workspace_id", "object_key", "profile_id"}},
		{table: "identity_profile_bindings", name: "uniq_identity_profile_binding_user", columns: []string{"workspace_id", "binding_key", "identity_user_id"}},
		{table: "identity_profile_binding_receipts", name: "uniq_identity_profile_binding_receipt", columns: []string{"workspace_id", "object_key", "profile_id", "operation", "idempotency_key"}},
		{table: "identity_profile_binding_events", name: "uniq_identity_profile_binding_event", columns: []string{"workspace_id", "object_key", "profile_id", "operation", "idempotency_key"}},
	} {
		if err := s.CreateIndexIfMissing(ctx, index.table, index.name, true, index.columns...); err != nil {
			return fmt.Errorf("create %s: %w", index.name, err)
		}
	}
	return nil
}
