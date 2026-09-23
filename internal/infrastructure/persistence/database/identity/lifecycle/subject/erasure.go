package subject

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sharedsubject "github.com/domainry/domainry-foundation/subjectlifecycle"
	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
	privacy "github.com/domainry/domainry-identity/internal/domain/privacy"
	lifecyclemodel "github.com/domainry/domainry-lifecycle-sdk/model"
	"github.com/domainry/domainry-orm/query"
)

const (
	sharedSubjectRequestsTable       = sharedsubject.RequestTableName
	sharedSubjectExecutionStepsTable = sharedsubject.StepTableName
	lifecycleSubjectOwner            = "lifecycle"
	subjectEraseFenceOperation       = "erase_fence"
	identitySubjectOwner             = "identity"
	subjectEraseOperation            = "erase"
)

func (s *Store) sharedSubjectFenceRequests(workspaceID, requestID, subjectID string) *query.SelectBuilder {
	requestIDs := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), sharedSubjectRequestsTable, workspaceID).Columns("id").Where(query.And(
		query.NotEqual("request_type", "external_erasure"),
		query.Equal("kind", "erase"),
		query.Equal("resolved_identity", subjectID),
	))
	return query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), sharedSubjectExecutionStepsTable, workspaceID).
		Columns("request_id").Where(query.And(
		query.Equal("request_id", requestID),
		query.Equal("owner", lifecycleSubjectOwner),
		query.Equal("operation", subjectEraseFenceOperation),
		query.InSubquery("request_id", requestIDs),
	))
}

type subjectErasureResult struct {
	SubjectID string `json:"subject_id"`
	RequestID string `json:"request_id"`
}

type subjectStepReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type subjectStepWriter interface {
	subjectStepReader
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *Store) sharedSubjectStep(ctx context.Context, reader subjectStepReader, workspaceID, requestID, operation string) (json.RawMessage, bool, error) {
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), sharedSubjectExecutionStepsTable, workspaceID).
		Columns("payload_json").Where(query.And(
		query.Equal("request_id", requestID),
		query.Equal("owner", identitySubjectOwner),
		query.Equal("operation", operation),
	)).Build()
	if err != nil {
		return nil, false, err
	}
	var raw string
	if err = reader.QueryRowContext(ctx, statement, args...).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	var step lifecyclemodel.SubjectExecutionStep
	if json.Unmarshal([]byte(raw), &step) != nil || step.WorkspaceID != workspaceID || step.RequestID != requestID || step.Owner != identitySubjectOwner || step.Operation != operation || !json.Valid(step.Payload) {
		return nil, false, fmt.Errorf("identity shared subject execution step invalid")
	}
	return append(json.RawMessage(nil), step.Payload...), true, nil
}

func (s *Store) saveSharedSubjectStep(ctx context.Context, writer subjectStepWriter, workspaceID, requestID, operation string, payload json.RawMessage) error {
	if !json.Valid(payload) {
		return fmt.Errorf("identity shared subject execution payload invalid")
	}
	if previous, found, err := s.sharedSubjectStep(ctx, writer, workspaceID, requestID, operation); err != nil {
		return err
	} else if found {
		if !bytes.Equal(previous, payload) {
			return fmt.Errorf("identity shared subject execution step payload conflict")
		}
		return nil
	}
	completedAt := time.Now().UTC()
	step := lifecyclemodel.SubjectExecutionStep{
		WorkspaceID: workspaceID,
		RequestID:   requestID,
		Owner:       identitySubjectOwner,
		Operation:   operation,
		Payload:     append(json.RawMessage(nil), payload...),
		CompletedAt: completedAt,
	}
	raw, err := json.Marshal(step)
	if err != nil {
		return err
	}
	statement, args, err := query.NewWorkspaceInsertBuilder(s.store.SQLRenderer(), sharedSubjectExecutionStepsTable, workspaceID).
		Columns("request_id", "owner", "operation", "payload_json", "completed_at").
		Values(requestID, identitySubjectOwner, operation, string(raw), completedAt.Format(time.RFC3339Nano)).Build()
	if err != nil {
		return err
	}
	_, err = writer.ExecContext(ctx, statement, args...)
	return err
}

func (s *Store) requireSharedSubjectFence(ctx context.Context, reader subjectStepReader, workspaceID, requestID, subjectID string) error {
	statement, args, err := s.sharedSubjectFenceRequests(workspaceID, requestID, subjectID).Build()
	if err != nil {
		return err
	}
	var fencedRequest string
	if err = reader.QueryRowContext(ctx, statement, args...).Scan(&fencedRequest); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("identity subject erasure requires Lifecycle fence")
	} else if err != nil {
		return err
	}
	return nil
}

func validateSubjectErasureResult(payload json.RawMessage, requestID, subjectID string) error {
	var result subjectErasureResult
	if json.Unmarshal(payload, &result) != nil || result.RequestID != requestID || result.SubjectID != subjectID {
		return fmt.Errorf("identity shared subject erasure result scope mismatch")
	}
	return nil
}

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
	if !s.store.SubjectLifecyclePersistenceBound() {
		return nil, fmt.Errorf("identity shared subject lifecycle persistence is not bound")
	}
	tx, err := s.store.DB().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if saved, found, err := s.sharedSubjectStep(ctx, tx, workspaceID, requestID, subjectEraseOperation); err != nil {
		return nil, err
	} else if found {
		if err := validateSubjectErasureResult(saved, requestID, userID); err != nil {
			return nil, err
		}
		return saved, nil
	}
	if err = s.requireSharedSubjectFence(ctx, tx, workspaceID, requestID, userID); err != nil {
		return nil, err
	}
	statement, args, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
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
	}
	if s.store.OperationsPersistenceBound() {
		updates = append(updates, query.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "_operations", workspaceID).
			Set("result_json", "{}").Set("status", "failed").Set("failure_class", "terminal").
			Set("error_code", "identity.subject_erased").Set("finished_at", now).Set("updated_at", now).
			Where(query.And(query.Equal("owner", "identity"), query.Equal("kind", "identity.auth_mutation"), query.Equal("resource_id", userID))))
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
	if err = s.saveSharedSubjectStep(ctx, tx, workspaceID, requestID, subjectEraseOperation, result); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) redactSubjectReceipts(ctx context.Context, tx *sql.Tx, workspaceID, userID string) error {
	type definition struct {
		table, column, owner string
		predicate            query.Predicate
	}
	definitions := []definition{{
		table: "_audit_events", column: "metadata_json",
		predicate: query.InExpression(query.Column("event"),
			"identity.profile_binding.invite", "identity.profile_binding.claim", "identity.profile_binding.bind",
			"identity.profile_binding.rebind", "identity.profile_binding.unlink",
		),
	}}
	if s.store.OperationsPersistenceBound() {
		definitions = append(definitions, definition{table: "_operations", column: "result_json", owner: "identity"})
	}
	for _, definition := range definitions {
		builder := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), definition.table, workspaceID).Columns("id", definition.column)
		predicates := []query.Predicate{}
		if definition.owner != "" {
			predicates = append(predicates, query.Equal("owner", definition.owner))
		}
		if definition.predicate != nil {
			predicates = append(predicates, definition.predicate)
		}
		if len(predicates) != 0 {
			builder.Where(query.And(predicates...))
		}
		statement, args, err := builder.Build()
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
				item["identity_user_id"] = nil
				if _, event := item["binding_version"]; !event {
					item["status"] = "unlinked"
				}
				changed = true
			}
			if item["user_id"] == userID {
				if _, exists := item["login_id"]; exists {
					item["login_id"] = identitypolicy.IdentityAnonymizedSubject(workspaceID, userID).Email
					changed = true
				}
			}
		}
		if item["initial_admin_user_id"] == userID {
			if _, exists := item["initial_admin_login_id"]; exists {
				item["initial_admin_login_id"] = identitypolicy.IdentityAnonymizedSubject(workspaceID, userID).Email
				changed = true
			}
		}
		if item["previous_user_id"] == userID {
			item["previous_user_id"] = nil
			if _, exists := item["reason"]; exists {
				item["reason"] = ""
			}
			changed = true
		}
		if item["actor_id"] == userID {
			item["actor_id"] = "erased-" + identitypolicy.IdentityAnonymizedSubject(workspaceID, userID).Token
			changed = true
		}
		for _, child := range item {
			if redactSubjectResult(child, workspaceID, userID) {
				changed = true
			}
		}
	}
	return changed
}
