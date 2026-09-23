package schema_test

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestAuthenticationProtocolsKeepDedicatedStoresAndSecurityIndexes(t *testing.T) {
	store, err := database.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite",
		DBPath:         filepath.Join(t.TempDir(), "identity.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	// These protocols intentionally have different persistence semantics. A
	// generic JSON credential table would lose their atomic consume, rotation,
	// replay and lockout constraints.
	for table, requiredColumns := range map[string][]string{
		"_identity_auth_refresh_tokens":      {"token_hash", "session_id", "revoked_at", "replaced_by_id", "expires_at"},
		"_identity_auth_authorization_codes": {"code_hash", "session_json", "redirect_url", "consumed_at", "expires_at"},
		"_identity_auth_assertion_replays":   {"replay_hash", "provider_key", "expires_at"},
		"_identity_auth_login_transactions":  {"state_hash", "payload_json", "attempts", "consumed_at", "expires_at"},
		"_identity_credentials":              {"password_hash", "failed_login_count", "locked_until"},
		"_identity_mfa_factors":              {"totp_secret", "totp_step", "totp_failures", "totp_locked_until"},
	} {
		columns, err := authProtocolSQLiteTableColumns(store.DB(), table)
		if err != nil {
			t.Fatalf("inspect %s: %v", table, err)
		}
		for _, column := range requiredColumns {
			if !columns[column] {
				t.Errorf("dedicated protocol table %s is missing %s", table, column)
			}
		}
	}

	for index, expectedColumns := range map[string][]string{
		"idx_auth_refresh_tokens_hash":        {"token_hash", "workspace_id"},
		"idx_auth_refresh_tokens_replaced_by": {"workspace_id", "replaced_by_id"},
		"idx_auth_login_transactions_state":   {"state_hash", "provider_key", "workspace_id"},
		"idx_auth_assertion_replays_expiry":   {"workspace_id", "expires_at"},
	} {
		actualColumns, err := authProtocolSQLiteIndexColumns(store.DB(), index)
		if err != nil {
			t.Fatalf("inspect %s: %v", index, err)
		}
		if !reflect.DeepEqual(actualColumns, expectedColumns) {
			t.Errorf("index %s columns=%v, want %v", index, actualColumns, expectedColumns)
		}
	}
	for table, expectedColumns := range map[string][]string{
		"_identity_auth_authorization_codes": {"workspace_id", "code_hash"},
		"_identity_auth_assertion_replays":   {"workspace_id", "replay_hash"},
	} {
		actualColumns, err := authProtocolSQLitePrimaryKeyColumns(store.DB(), table)
		if err != nil {
			t.Fatalf("inspect %s primary key: %v", table, err)
		}
		if !reflect.DeepEqual(actualColumns, expectedColumns) {
			t.Errorf("table %s primary key=%v, want %v", table, actualColumns, expectedColumns)
		}
	}
}

func authProtocolSQLitePrimaryKeyColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := []string{}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	return columns, rows.Err()
}

func authProtocolSQLiteTableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns[column] = true
	}
	return columns, rows.Err()
}

func authProtocolSQLiteIndexColumns(db *sql.DB, index string) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := []string{}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	return columns, rows.Err()
}
