package schema

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
	ormschema "github.com/domainry/domainry-orm/schema"
)

func EnsureIdentitySchema(ctx context.Context, s Store) error {
	text := s.MetadataIDColumnType()
	types := s.SchemaTypes()
	boolType, boolFalse := types.Boolean, types.FalseLiteral
	defaultText, identityIndexText := types.DefaultText, types.IndexedText
	tables := map[string][]string{
		"_identity_organization_units": {
			"id " + text + " PRIMARY KEY",
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
		"_identity_workflow_workload_bindings": {
			"id " + text + " PRIMARY KEY",
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
			"created_at " + text + " NOT NULL",
			"updated_at " + text + " NOT NULL",
			"deactivated_at " + text,
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
			"authentication_time BIGINT NOT NULL DEFAULT 0",
			"authentication_methods TEXT NOT NULL DEFAULT '[]'",
			"assurance_level " + text + " NOT NULL DEFAULT ''",
			"token_hash " + identityIndexText + " NOT NULL",
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
			"subject_key_hash " + text,
			"challenge_status " + text + " NOT NULL DEFAULT 'active'",
			"challenge_purpose " + text + " NOT NULL DEFAULT 'login'",
			"delivery_ref " + text,
			"delivery_error " + text,
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
	}
	workspaceIdentities := prepareWorkspaceScopedIdentities(tables)
	// These baseline tables use engine-provided physical types that
	// domainry-orm cannot yet express as a custom ColumnType.
	for _, table := range sortedSchemaTables(tables) {
		if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier(table)+" ("+quotedColumnDefinitions(s, tables[table])+")"); err != nil {
			return fmt.Errorf("create %s: %w", table, err)
		}
	}
	if err := ensureIdentityGlobalLoginNames(ctx, s); err != nil {
		return err
	}
	if err := ensureIdentityOrganizationUnitSiblingKeys(ctx, s); err != nil {
		return err
	}
	if err := s.EnsureCompositePrimaryKey(ctx, "_identity_auth_provider_credentials", "workspace_id", "provider_key"); err != nil {
		return fmt.Errorf("ensure workspace auth provider credential identity: %w", err)
	}
	if err := ensureWorkspaceScopedIdentities(ctx, s, workspaceIdentities); err != nil {
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
	if err := s.CreateIndexIfMissing(ctx, "_identity_workflow_workload_bindings", "uniq_identity_workflow_workload", true, "workspace_id", "application_key", "workflow_key"); err != nil {
		return fmt.Errorf("create Identity workflow workload uniqueness index: %w", err)
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
		{table: "_identity_menus", name: "idx_identity_menus_parent", columns: []string{"workspace_id", "parent_id"}},
		{table: "_identity_role_menu_assignments", name: "idx_identity_role_menus_role", columns: []string{"workspace_id", "role_id"}},
		{table: "_identity_role_menu_assignments", name: "idx_identity_role_menus_menu", columns: []string{"workspace_id", "menu_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_hash", columns: []string{"token_hash", "workspace_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_user", columns: []string{"workspace_id", "user_id"}},
		{table: "_identity_auth_refresh_tokens", name: "idx_auth_refresh_tokens_replaced_by", columns: []string{"workspace_id", "replaced_by_id"}},
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
	if err := ensureIdentityTOTPSchema(ctx, s); err != nil {
		return err
	}
	if err := ensureIdentityApplicationsSchema(ctx, s); err != nil {
		return err
	}
	return nil
}

func ensureIdentityOrganizationUnitSiblingKeys(ctx context.Context, s Store) error {
	const table = "_identity_organization_units"
	columns, err := s.TableColumns(ctx, table)
	if err != nil {
		return fmt.Errorf("inspect Identity organization-unit sibling key: %w", err)
	}
	if !columns["sibling_key"] {
		definition := ormschema.Column("sibling_key", ormschema.TextKey(64)).NotNull().DefaultValue("")
		statement, arguments, buildErr := ormschema.NewAddColumn(s.SchemaRenderer(), table, definition).Build()
		if buildErr != nil {
			return fmt.Errorf("build Identity organization-unit sibling key column: %w", buildErr)
		}
		if _, execErr := s.SchemaDB().ExecContext(ctx, statement, arguments...); execErr != nil {
			return fmt.Errorf("add Identity organization-unit sibling key column: %w", execErr)
		}
	}

	statement, arguments, err := query.NewSelectBuilder(s.SchemaRenderer(), table).
		Columns("id", "workspace_id", "parent_id", "name", "sibling_key").Build()
	if err != nil {
		return fmt.Errorf("build Identity organization-unit sibling key backfill query: %w", err)
	}
	rows, err := s.SchemaDB().QueryContext(ctx, statement, arguments...)
	if err != nil {
		return fmt.Errorf("query Identity organization-unit sibling key backfill: %w", err)
	}
	type organizationUnitSibling struct {
		id, workspaceID, name, currentKey string
		parentID                          sql.NullString
	}
	items := []organizationUnitSibling{}
	for rows.Next() {
		var item organizationUnitSibling
		if scanErr := rows.Scan(&item.id, &item.workspaceID, &item.parentID, &item.name, &item.currentKey); scanErr != nil {
			_ = rows.Close()
			return fmt.Errorf("scan Identity organization-unit sibling key backfill: %w", scanErr)
		}
		items = append(items, item)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate Identity organization-unit sibling key backfill: %w", rowsErr)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return fmt.Errorf("close Identity organization-unit sibling key backfill: %w", closeErr)
	}
	for _, item := range items {
		var parentID *string
		if item.parentID.Valid {
			value := item.parentID.String
			parentID = &value
		}
		expected := identitymodel.IdentityOrganizationUnitSiblingKey(parentID, item.name)
		if item.currentKey == expected {
			continue
		}
		update, updateArguments, buildErr := query.NewWorkspaceUpdateBuilder(s.SchemaRenderer(), table, item.workspaceID).
			Set("sibling_key", expected).Where(query.Equal("id", item.id)).Build()
		if buildErr != nil {
			return fmt.Errorf("build Identity organization-unit sibling key backfill update: %w", buildErr)
		}
		if _, execErr := s.SchemaDB().ExecContext(ctx, update, updateArguments...); execErr != nil {
			return fmt.Errorf("backfill Identity organization-unit sibling key: %w", execErr)
		}
	}
	return nil
}

func ensureIdentityTOTPSchema(ctx context.Context, s Store) error {
	const table = "_identity_mfa_factors"
	columns, err := s.TableColumns(ctx, table)
	if err != nil {
		return err
	}
	for _, name := range []string{"totp_secret", "totp_step", "totp_failures", "totp_locked_until"} {
		if columns[name] {
			continue
		}
		definition := ormschema.Column(name, ormschema.Text())
		if name == "totp_step" {
			definition = ormschema.Column(name, ormschema.BigInt()).NotNull().DefaultValue(-1)
		}
		if name == "totp_failures" {
			definition = ormschema.Column(name, ormschema.Integer()).NotNull().DefaultValue(0)
		}
		statement, args, err := ormschema.NewAddColumn(s.SchemaRenderer(), table, definition).Build()
		if err != nil {
			return err
		}
		if _, err := s.SchemaDB().ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	return nil
}
