package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	identitypolicy "github.com/domainry/domainry-identity/internal/domain/identity/policy"
	privacy "github.com/domainry/domainry-identity/internal/domain/privacy"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type lifecycleSQLStore interface {
	DB() *sql.DB
	Identifier(string) string
	TableIdentifier(string) string
	Placeholder(int) string
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
}

type IdentitySubjectLifecycleStore struct{ store lifecycleSQLStore }

func NewIdentitySubjectLifecycleStore(store lifecycleSQLStore) *IdentitySubjectLifecycleStore {
	return &IdentitySubjectLifecycleStore{store: store}
}
func (s *IdentitySubjectLifecycleStore) Owner(context.Context) string { return "identity" }

func (s *IdentitySubjectLifecycleStore) ResolveSubject(ctx context.Context, workspaceID, subjectType, subjectID string) (string, error) {
	if subjectType != "user" {
		return "", fmt.Errorf("unsupported subject type %s", subjectType)
	}
	query := "SELECT " + s.store.Identifier("id") + " FROM " + s.store.TableIdentifier("identity_users") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND (" + s.store.Identifier("id") + " = " + s.store.Placeholder(2) + " OR " + s.store.Identifier("email") + " = " + s.store.Placeholder(3) + ")"
	var userID string
	if err := s.store.DB().QueryRowContext(ctx, query, workspaceID, subjectID, subjectID).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("subject identity not found")
	} else if err != nil {
		return "", err
	}
	return userID, nil
}

func (s *IdentitySubjectLifecycleStore) PreviewSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	counts := map[string]int64{}
	for name, table := range map[string]string{"users": "identity_users", "credentials": "identity_credentials", "external_accounts": "identity_external_accounts", "mfa_factors": "identity_mfa_factors", "refresh_tokens": "auth_refresh_tokens", "role_assignments": "identity_user_role_assignments"} {
		column := "user_id"
		if table == "identity_users" {
			column = "id"
		}
		query := "SELECT COUNT(*) FROM " + s.store.TableIdentifier(table) + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier(column) + " = " + s.store.Placeholder(2)
		var count int64
		if err := s.store.DB().QueryRowContext(ctx, query, workspaceID, userID).Scan(&count); err != nil {
			return nil, err
		}
		counts[name] = count
	}
	raw, _ := json.Marshal(counts)
	return raw, nil
}

func (s *IdentitySubjectLifecycleStore) ExportSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	query := "SELECT " + joinIdentityColumns(s.store, []string{
		"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale",
		"email", "phone", "account_type", "locale", "timezone", "status",
	}) + ", " + s.store.Identifier("version") + ", " + joinIdentityColumns(s.store, []string{"created_at", "updated_at"}) +
		" FROM " + s.store.TableIdentifier("identity_users") + " WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) + " AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(2)
	var values [17]string
	var version int64
	if err := s.store.DB().QueryRowContext(ctx, query, workspaceID, userID).Scan(
		&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8],
		&values[9], &values[10], &values[11], &values[12], &values[13], &values[14], &version, &values[15], &values[16],
	); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"id": values[0], "name": values[1], "given_name": values[2], "middle_name": values[3], "family_name": values[4],
		"name_prefix": values[5], "name_suffix": values[6], "native_name": values[7], "name_locale": values[8],
		"email": values[9], "phone": values[10], "account_type": values[11], "locale": values[12], "timezone": values[13],
		"status": values[14], "version": version, "created_at": values[15], "updated_at": values[16],
	}
	preview, err := s.PreviewSubject(ctx, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	payload["related_counts"] = json.RawMessage(preview)
	relationships, err := s.exportSubjectRelationships(ctx, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	for key, value := range relationships {
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	return raw, nil
}

func (s *IdentitySubjectLifecycleStore) exportSubjectRelationships(ctx context.Context, workspaceID, userID string) (map[string]any, error) {
	queries := []struct {
		key     string
		columns []string
		query   string
	}{
		{
			key: "workforce_profiles", columns: []string{"id", "organization_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id"},
			query: "SELECT " + joinIdentityColumns(s.store, []string{"id", "organization_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id"}) +
				" FROM " + s.store.TableIdentifier("identity_workforce_profiles") +
				" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
				" AND " + s.store.Identifier("identity_user_id") + " = " + s.store.Placeholder(2) +
				" ORDER BY " + s.store.Identifier("id"),
		},
		{
			key: "workforce_assignments", columns: []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status"},
			query: "SELECT " + joinIdentityColumns(s.store, []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status"}) +
				" FROM " + s.store.TableIdentifier("identity_workforce_assignments") +
				" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
				" AND " + s.store.Identifier("workforce_profile_id") + " IN (SELECT " + s.store.Identifier("id") +
				" FROM " + s.store.TableIdentifier("identity_workforce_profiles") +
				" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(2) +
				" AND " + s.store.Identifier("identity_user_id") + " = " + s.store.Placeholder(3) + ")" +
				" ORDER BY " + s.store.Identifier("id"),
		},
		{
			key: "role_assignments", columns: []string{"id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason"},
			query: "SELECT " + joinIdentityColumns(s.store, []string{"id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason"}) +
				" FROM " + s.store.TableIdentifier("identity_user_role_assignments") +
				" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
				" AND " + s.store.Identifier("user_id") + " = " + s.store.Placeholder(2) +
				" ORDER BY " + s.store.Identifier("id"),
		},
		{
			key: "profile_relations", columns: []string{"id", "binding_key", "object_key", "profile_id", "status", "invitation_channel", "claim_proof_type"},
			query: "SELECT " + joinIdentityColumns(s.store, []string{"id", "binding_key", "object_key", "profile_id", "status", "invitation_channel", "claim_proof_type"}) +
				" FROM " + s.store.TableIdentifier("identity_profile_bindings") +
				" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(1) +
				" AND " + s.store.Identifier("identity_user_id") + " = " + s.store.Placeholder(2) +
				" ORDER BY " + s.store.Identifier("id"),
		},
	}
	result := make(map[string]any, len(queries))
	for _, definition := range queries {
		args := []any{workspaceID, userID}
		if definition.key == "workforce_assignments" {
			args = []any{workspaceID, workspaceID, userID}
		}
		rows, err := s.store.DB().QueryContext(ctx, definition.query, args...)
		if err != nil {
			return nil, err
		}
		items := []map[string]string{}
		for rows.Next() {
			values := make([]string, len(definition.columns))
			destinations := make([]any, len(values))
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				rows.Close()
				return nil, err
			}
			item := make(map[string]string, len(values))
			for index, column := range definition.columns {
				item[column] = values[index]
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		result[definition.key] = items
	}
	return result, nil
}

func (s *IdentitySubjectLifecycleStore) EraseSubject(ctx context.Context, workspaceID, userID string, _ []privacy.LegalHold) (json.RawMessage, error) {
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, table := range []string{"auth_refresh_tokens", "identity_credentials", "identity_external_accounts", "identity_mfa_factors", "identity_user_role_assignments"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.store.TableIdentifier(table)+" WHERE "+s.store.Identifier("workspace_id")+" = "+s.store.Placeholder(1)+" AND "+s.store.Identifier("user_id")+" = "+s.store.Placeholder(2), workspaceID, userID); err != nil {
			return nil, err
		}
	}
	anonymized := identitypolicy.IdentityAnonymizedSubject(workspaceID, userID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	query := "UPDATE " + s.store.TableIdentifier("identity_users") + " SET " +
		s.store.Identifier("name") + " = " + s.store.Placeholder(1) + ", " +
		s.store.Identifier("given_name") + " = '', " + s.store.Identifier("middle_name") + " = '', " + s.store.Identifier("family_name") + " = '', " +
		s.store.Identifier("name_prefix") + " = '', " + s.store.Identifier("name_suffix") + " = '', " + s.store.Identifier("native_name") + " = '', " + s.store.Identifier("name_locale") + " = '', " +
		s.store.Identifier("email") + " = " + s.store.Placeholder(2) + ", " + s.store.Identifier("phone") + " = '', " +
		s.store.Identifier("locale") + " = '', " + s.store.Identifier("timezone") + " = '', " +
		s.store.Identifier("status") + " = 'erased', " + s.store.Identifier("version") + " = " + s.store.Identifier("version") + " + 1, " + s.store.Identifier("updated_at") + " = " + s.store.Placeholder(3) +
		" WHERE " + s.store.Identifier("workspace_id") + " = " + s.store.Placeholder(4) + " AND " + s.store.Identifier("id") + " = " + s.store.Placeholder(5)
	result, err := tx.ExecContext(ctx, query, anonymized.Name, anonymized.Email, now, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, fmt.Errorf("subject identity not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"anonymized":1,"credentials_deleted":true}`), nil
}

func joinIdentityColumns(store lifecycleSQLStore, columns []string) string {
	result := ""
	for index, column := range columns {
		if index > 0 {
			result += ", "
		}
		result += "COALESCE(" + store.Identifier(column) + ", '')"
	}
	return result
}
