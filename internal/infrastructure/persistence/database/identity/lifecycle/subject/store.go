package subject

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	BindSubjectLifecyclePersistence()
	SubjectLifecyclePersistenceBound() bool
	OperationsPersistenceBound() bool
}

type AuthenticationEraser func(context.Context, *sql.Tx, string, string, string) error

type Store struct {
	store               Backend
	eraseAuthentication AuthenticationEraser
}

func New(store Backend, eraseAuthentication AuthenticationEraser) *Store {
	return &Store{store: store, eraseAuthentication: eraseAuthentication}
}
func (s *Store) Owner(context.Context) string { return "identity" }

func (s *Store) BindSubjectLifecyclePersistence() {
	s.store.BindSubjectLifecyclePersistence()
}

func (s *Store) SubjectLifecyclePersistenceBound() bool {
	return s.store.SubjectLifecyclePersistenceBound()
}

func (s *Store) ResolveSubject(ctx context.Context, workspaceID, subjectType, subjectID string) (string, error) {
	if subjectType != "user" {
		return "", fmt.Errorf("unsupported subject type %s", subjectType)
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
		Columns("id").Where(query.Or(query.Equal("id", subjectID), query.Equal("email", subjectID))).Build()
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

func (s *Store) PreviewSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	counts := map[string]int64{}
	for name, table := range map[string]string{"users": "_identity_users", "credentials": "_identity_credentials", "external_accounts": "_identity_external_accounts", "mfa_factors": "_identity_mfa_factors", "refresh_tokens": "_identity_auth_refresh_tokens", "role_assignments": "_identity_user_role_assignments"} {
		column := "user_id"
		if table == "_identity_users" {
			column = "id"
		}
		statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), table, workspaceID).
			Projections(query.Project(query.CountAll())).Where(query.Equal(column, userID)).Build()
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

func (s *Store) ExportSubject(ctx context.Context, workspaceID, userID string) (json.RawMessage, error) {
	stringColumns := []string{"id", "name", "given_name", "middle_name", "family_name", "name_prefix", "name_suffix", "native_name", "name_locale", "email", "phone", "account_type", "locale", "timezone", "org_id", "support_org_id", "manager_user_id", "reporting_path", "worker_no", "worker_type", "work_status", "start_date", "end_date", "status"}
	projections := coalescedIdentityProjections(stringColumns...)
	projections = append(projections, query.Project(query.Column("version")))
	projections = append(projections, coalescedIdentityProjections("created_at", "updated_at")...)
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.store.SQLRenderer(), "_identity_users", workspaceID).
		Projections(projections...).Where(query.Equal("id", userID)).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity subject export query: %w", err)
	}
	var values [26]string
	var version int64
	if err := s.store.DB().QueryRowContext(ctx, statement, arguments...).Scan(
		&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8],
		&values[9], &values[10], &values[11], &values[12], &values[13], &values[14], &values[15], &values[16], &values[17], &values[18], &values[19], &values[20], &values[21], &values[22], &values[23], &version, &values[24], &values[25],
	); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"id": values[0], "name": values[1], "given_name": values[2], "middle_name": values[3], "family_name": values[4],
		"name_prefix": values[5], "name_suffix": values[6], "native_name": values[7], "name_locale": values[8],
		"email": values[9], "phone": values[10], "account_type": values[11], "locale": values[12], "timezone": values[13],
		"org_id": values[14], "support_org_id": values[15], "manager_user_id": values[16], "reporting_path": values[17],
		"worker_no": values[18], "worker_type": values[19], "work_status": values[20],
		"start_date": values[21], "end_date": values[22], "status": values[23], "version": version, "created_at": values[24], "updated_at": values[25],
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

func (s *Store) exportSubjectRelationships(ctx context.Context, workspaceID, userID string) (map[string]any, error) {
	definitions := []struct {
		key     string
		columns []string
		builder *query.SelectBuilder
	}{
		{"role_assignments", []string{"id", "role_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason"},
			identityRelationshipSelect(s.store.SQLRenderer(), "_identity_user_role_assignments", workspaceID, []string{"id", "role_id", "binding_key", "profile_id", "source", "status", "valid_from", "valid_until", "granted_by", "grant_reason", "revoked_by", "revoked_at", "revoke_reason"}).Where(query.Equal("user_id", userID))},
		{"profile_relations", []string{"id", "binding_key", "object_key", "profile_id", "status", "invitation_channel", "claim_proof_type"},
			identityRelationshipSelect(s.store.SQLRenderer(), "_identity_profile_bindings", workspaceID, []string{"id", "binding_key", "object_key", "profile_id", "status", "invitation_channel", "claim_proof_type"}).Where(query.Equal("identity_user_id", userID))},
	}
	result := make(map[string]any, len(definitions))
	for _, definition := range definitions {
		statement, arguments, err := definition.builder.OrderBy(query.Ascending("id")).Build()
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

func (s *Store) ExportRelationships(ctx context.Context, workspaceID, userID string) (map[string]any, error) {
	return s.exportSubjectRelationships(ctx, workspaceID, userID)
}

func identityRelationshipSelect(renderer ormdialect.Renderer, table, workspaceID string, columns []string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(renderer, table, workspaceID).Projections(coalescedIdentityProjections(columns...)...)
}

func coalescedIdentityProjections(columns ...string) []query.Projection {
	projections := make([]query.Projection, len(columns))
	for index, column := range columns {
		projections[index] = query.Project(query.Coalesce(query.Column(column), query.Value("")))
	}
	return projections
}
