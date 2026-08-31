package department

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*query.InsertBuilder, []string, ...string) *query.InsertBuilder
	QueryIdentityContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) *Store { return &Store{backend: backend, now: now} }

func (s *Store) Upsert(ctx context.Context, execer Execer, workspaceID string, item identitymodel.IdentityDepartment) error {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if item.ID == "" {
		return fmt.Errorf("department id is required")
	}
	if item.Status == "" {
		item.Status = identitymodel.IdentityStatusActive
	}
	ancestors, _ := json.Marshal(item.AncestorIDs)
	insert := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_departments", workspace.String()).
		Columns("id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at").
		Values(item.ID, item.Name, nullablePointer(item.ParentID), nullable(item.LeaderWorkforceProfileID), item.Path, string(ancestors), item.Depth, item.SortOrder, string(item.Status), s.now(), s.now())
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity department upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) List(ctx context.Context, workspaceID string) ([]identitymodel.IdentityDepartment, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_departments", workspace.String()).
		Columns("id", "name", "parent_id", "leader_workforce_profile_id", "path", "ancestor_ids", "depth", "sort_order", "status").
		OrderBy(query.Ascending("depth"), query.Ascending("parent_id"), query.Ascending("sort_order"), query.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity departments query: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityDepartment{}
	for rows.Next() {
		var item identitymodel.IdentityDepartment
		var parentID, leaderID sql.NullString
		var ancestors string
		if err := rows.Scan(&item.ID, &item.Name, &parentID, &leaderID, &item.Path, &ancestors, &item.Depth, &item.SortOrder, &item.Status); err != nil {
			return nil, err
		}
		if parentID.Valid {
			value := parentID.String
			item.ParentID = &value
		}
		item.LeaderWorkforceProfileID = leaderID.String
		_ = json.Unmarshal([]byte(ancestors), &item.AncestorIDs)
		out = append(out, item)
	}
	return out, rows.Err()
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
func nullablePointer(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return *value
}
