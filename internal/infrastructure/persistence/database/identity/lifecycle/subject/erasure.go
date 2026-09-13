package subject

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
	privacy "github.com/domainry/domainry-identity/internal/domain/privacy"
	"github.com/domainry/domainry-orm/query"
)

// EraseSubject has one stable request identity even when called without a
// Lifecycle request. All destructive entry points use the same transaction.
func (s *Store) EraseSubject(ctx context.Context, workspaceID, userID string, holds []privacy.LegalHold) (json.RawMessage, error) {
	return s.EraseSubjectForRequest(ctx, "subject:"+userID, workspaceID, userID, holds)
}

func (s *Store) EraseSubjectForRequest(ctx context.Context, requestID, workspaceID, userID string, holds []privacy.LegalHold) (json.RawMessage, error) {
	if strings.TrimSpace(requestID) == "" || strings.TrimSpace(workspaceID) == "" || strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("identity subject erasure request and scope are required")
	}
	if len(holds) != 0 {
		return nil, fmt.Errorf("identity subject erasure is blocked by legal holds")
	}
	if s.eraseAuthentication == nil {
		return nil, fmt.Errorf("identity authentication erasure is unavailable")
	}
	tx, err := s.store.DB().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_subject_erasure_receipts", workspaceID).
		Columns("subject_id", "result_json").Where(query.Equal("request_id", requestID)).Build()
	if err != nil {
		return nil, err
	}
	var savedSubject, savedResult string
	err = tx.QueryRowContext(ctx, statement, args...).Scan(&savedSubject, &savedResult)
	if err == nil {
		if savedSubject != userID {
			return nil, fmt.Errorf("identity subject erasure request conflict")
		}
		return json.RawMessage(savedResult), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	statement, args, err = query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
		Projections(coalescedIdentityProjections("phone", "status")...).Where(query.Equal("id", userID)).Build()
	if err != nil {
		return nil, err
	}
	var phone, status string
	if err = tx.QueryRowContext(ctx, statement, args...).Scan(&phone, &status); err != nil {
		return nil, err
	}
	if err = s.eraseAuthentication(ctx, tx, workspaceID, userID, phone); err != nil {
		return nil, err
	}
	for _, table := range []string{"_identity_auth_refresh_tokens", "_identity_credentials", "_identity_external_accounts", "_identity_mfa_factors", "_identity_user_role_assignments", "_identity_role_requests"} {
		statement, args, err = query.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), table, workspaceID).Where(query.Equal("user_id", userID)).Build()
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
			return nil, err
		}
	}
	anonymized := identitypolicy.IdentityAnonymizedSubject(workspaceID, userID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if status != "erased" {
		update := query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
			Set("name", anonymized.Name).Set("email", anonymized.Email).Set("status", "erased").
			SetExpression("version", query.Add(query.Column("version"), query.Value(1))).Set("updated_at", now)
		for _, column := range []string{"given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "phone", "locale", "timezone", "reporting_path", "worker_no", "worker_type", "work_status"} {
			update.Set(column, "")
		}
		for _, column := range []string{"login_name_key", "org_id", "support_org_id", "manager_user_id", "start_date", "end_date"} {
			update.Set(column, nil)
		}
		statement, args, err = update.Where(query.Equal("id", userID)).Build()
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
			return nil, err
		}
	}
	// Preserve idempotency keys so replaying an earlier create cannot resurrect
	// the account. Only their source-owned result data is redacted.
	if err = s.redactSubjectReceipts(ctx, tx, workspaceID, userID); err != nil {
		return nil, err
	}
	updates := []*query.UpdateBuilder{
		query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_profile_bindings", workspaceID).
			Set("status", "unlinked").Set("identity_user_id", nil).Set("invitation_channel", "").Set("claim_proof_type", "").Set("updated_at", now).
			SetExpression("version", query.Add(query.Column("version"), query.Value(1))).Where(query.Equal("identity_user_id", userID)),
		query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_profile_binding_events", workspaceID).
			Set("reason", "").Where(query.Or(query.Equal("identity_user_id", userID), query.Equal("previous_user_id", userID))),
		query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_auth_mutation_receipts", workspaceID).
			Set("result_json", "{}").Set("status", "failed").Set("error_code", "identity.subject_erased").Set("updated_at", now).
			Where(query.Equal("target_id", userID)),
		query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_workspace_bootstrap_receipts", workspaceID).
			Set("initial_admin_login_id", anonymized.Email).Where(query.Equal("initial_admin_user_id", userID)),
		query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_identity_installation_administrator_bootstrap_receipts", workspaceID).
			Set("login_id", anonymized.Email).Where(query.Equal("user_id", userID)),
	}
	for _, update := range updates {
		statement, args, err = update.Build()
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
			return nil, err
		}
	}
	result, err := json.Marshal(map[string]any{"subject_id": userID, "request_id": requestID, "anonymized": 1, "credentials_deleted": true})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(workspaceID + "\x00" + requestID))
	statement, args, err = query.NewInsertBuilder(s.store.SQLRenderer(), "_identity_subject_erasure_receipts").
		Columns("id", "workspace_id", "request_id", "subject_id", "result_json", "created_at").
		Values(hex.EncodeToString(digest[:]), workspaceID, requestID, userID, string(result), now).Build()
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) redactSubjectReceipts(ctx context.Context, tx *sql.Tx, workspaceID, userID string) error {
	for _, definition := range []struct{ table, column string }{
		{"_identity_handler_deliveries", "result_json"}, {"_identity_authoring_receipts", "result_json"},
		{"_identity_entitlement_batch_receipts", "result_json"}, {"_identity_profile_binding_receipts", "binding_json"},
	} {
		statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), definition.table, workspaceID).Columns("id", definition.column).Build()
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, statement, args...)
		if err != nil {
			return err
		}
		type replacement struct{ id, raw string }
		var replacements []replacement
		for rows.Next() {
			var id, raw string
			if err = rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return err
			}
			var value any
			decoder := json.NewDecoder(strings.NewReader(raw))
			decoder.UseNumber()
			if err = decoder.Decode(&value); err != nil {
				rows.Close()
				return err
			}
			if redactSubjectResult(value, workspaceID, userID) {
				encoded, err := json.Marshal(value)
				if err != nil {
					rows.Close()
					return err
				}
				replacements = append(replacements, replacement{id, string(encoded)})
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, replacement := range replacements {
			statement, args, err = query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), definition.table, workspaceID).
				Set(definition.column, replacement.raw).Where(query.Equal("id", replacement.id)).Build()
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func redactSubjectResult(value any, workspaceID, userID string) bool {
	changed := false
	switch item := value.(type) {
	case []any:
		for _, child := range item {
			if redactSubjectResult(child, workspaceID, userID) {
				changed = true
			}
		}
	case map[string]any:
		if item["id"] == userID {
			// A source-owned user snapshot is reduced to its tombstone. Preserve
			// version and ID for callers checking the original delivery receipt.
			version := item["version"]
			for key := range item {
				delete(item, key)
			}
			anon := identitypolicy.IdentityAnonymizedSubject(workspaceID, userID)
			item["id"], item["name"], item["email"], item["status"] = userID, anon.Name, anon.Email, "erased"
			if version != nil {
				item["version"] = version
			}
			return true
		}
		if item["user_id"] == userID || item["identity_user_id"] == userID {
			for _, key := range []string{"reason", "grant_reason", "revoke_reason", "invitation_channel", "claim_proof_type"} {
				if _, exists := item[key]; exists {
					item[key] = ""
					changed = true
				}
			}
			if item["identity_user_id"] == userID {
				item["identity_user_id"], item["status"] = nil, "unlinked"
				changed = true
			}
		}
		for _, child := range item {
			if redactSubjectResult(child, workspaceID, userID) {
				changed = true
			}
		}
	}
	return changed
}
