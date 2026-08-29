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
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_users", workspaceID).
		Columns("id").Where(ormbuilder.Or(ormbuilder.Equal("id", subjectID), ormbuilder.Equal("email", subjectID))).Build()
	if err != nil {
		return "", fmt.Errorf("build identity subject resolution query: %w", err)
	}
	var userID string
	if err := s.store.DB().QueryRowContext(ctx, statement, arguments...).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
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
		statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), table, workspaceID).
			Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal(column, userID)).Build()
		if err != nil {
			return nil, fmt.Errorf("build identity subject preview query: %w", err)
		}
		var count int64
		if err := s.store.DB().QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
			return nil, err
		}
		counts[name] = count
	}
	raw, _ := json.Marshal(counts)
	return raw, nil
}

func (s *IdentitySubjectLifecycleStore) ExportSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	stringColumns := []string{"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "status"}
	projections := coalescedIdentityProjections(stringColumns...)
	projections = append(projections, ormbuilder.Project(ormbuilder.Column("version")))
	projections = append(projections, coalescedIdentityProjections("created_at", "updated_at")...)
	statement, arguments, err := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_users", workspaceID).
		Projections(projections...).Where(ormbuilder.Equal("id", userID)).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity subject export query: %w", err)
	}
	var values [17]string
	var version int64
	if err := s.store.DB().QueryRowContext(ctx, statement, arguments...).Scan(
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
	profileIDs := ormbuilder.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "identity_workforce_profiles", workspaceID).
		Columns("id").Where(ormbuilder.Equal("identity_user_id", userID))
	definitions := []struct {
		key     string
		columns []string
		builder *ormbuilder.SelectBuilder
	}{
		{"workforce_profiles", []string{"id", "organization_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id"},
			identityRelationshipSelect(s.store.SQLRenderer(), "identity_workforce_profiles", workspaceID, []string{"id", "organization_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id"}).Where(ormbuilder.Equal("identity_user_id", userID))},
		{"workforce_assignments", []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status"},
			identityRelationshipSelect(s.store.SQLRenderer(), "identity_workforce_assignments", workspaceID, []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status"}).Where(ormbuilder.InSubquery("workforce_profile_id", profileIDs))},
		{"role_assignments", []string{"id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason"},
			identityRelationshipSelect(s.store.SQLRenderer(), "identity_user_role_assignments", workspaceID, []string{"id", "role_id", "workforce_profile_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason"}).Where(ormbuilder.Equal("user_id", userID))},
		{"profile_relations", []string{"id", "binding_key", "object_key", "profile_id", "status", "invitation_channel", "claim_proof_type"},
			identityRelationshipSelect(s.store.SQLRenderer(), "identity_profile_bindings", workspaceID, []string{"id", "binding_key", "object_key", "profile_id", "status", "invitation_channel", "claim_proof_type"}).Where(ormbuilder.Equal("identity_user_id", userID))},
	}
	result := make(map[string]any, len(definitions))
	for _, definition := range definitions {
		statement, arguments, err := definition.builder.OrderBy(ormbuilder.Ascending("id")).Build()
		if err != nil {
			return nil, fmt.Errorf("build identity subject %s export query: %w", definition.key, err)
		}
		rows, err := s.store.DB().QueryContext(ctx, statement, arguments...)
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

func identityRelationshipSelect(renderer ormdialect.Renderer, table, workspaceID string, columns []string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(renderer, table, workspaceID).Projections(coalescedIdentityProjections(columns...)...)
}

func coalescedIdentityProjections(columns ...string) []ormbuilder.Projection {
	projections := make([]ormbuilder.Projection, len(columns))
	for index, column := range columns {
		projections[index] = ormbuilder.Project(ormbuilder.Coalesce(ormbuilder.Column(column), ormbuilder.Value("")))
	}
	return projections
}

func (s *IdentitySubjectLifecycleStore) EraseSubject(ctx context.Context, workspaceID, userID string, _ []privacy.LegalHold) (json.RawMessage, error) {
	tx, err := s.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, table := range []string{"auth_refresh_tokens", "identity_credentials", "identity_external_accounts", "identity_mfa_factors", "identity_user_role_assignments"} {
		statement, arguments, buildErr := ormbuilder.NewWorkspaceDeleteBuilder(s.store.SQLRenderer(), table, workspaceID).Where(ormbuilder.Equal("user_id", userID)).Build()
		if buildErr != nil {
			return nil, fmt.Errorf("build identity subject relation erase: %w", buildErr)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return nil, err
		}
	}
	anonymized := identitypolicy.IdentityAnonymizedSubject(workspaceID, userID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(s.store.SQLRenderer(), "identity_users", workspaceID).
		Set("name", anonymized.Name).Set("given_name", "").Set("middle_name", "").Set("family_name", "").
		Set("name_prefix", "").Set("name_suffix", "").Set("native_name", "").Set("name_locale", "").
		Set("email", anonymized.Email).Set("phone", "").Set("locale", "").Set("timezone", "").Set("status", "erased").
		SetExpression("version", ormbuilder.Add(ormbuilder.Column("version"), ormbuilder.Value(1))).Set("updated_at", now).
		Where(ormbuilder.Equal("id", userID)).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity subject anonymization: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
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
