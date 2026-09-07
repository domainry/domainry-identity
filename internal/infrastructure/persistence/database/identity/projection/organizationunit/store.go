package organizationunit

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
	QueryIdentityRowContext(context.Context, string, ...any) *sql.Row
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type Store struct {
	backend Backend
	now     func() string
}

func New(backend Backend, now func() string) *Store { return &Store{backend: backend, now: now} }

func (s *Store) Upsert(ctx context.Context, execer Execer, workspaceID string, item identitymodel.IdentityOrganizationUnit) error {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if item.ID == "" {
		return fmt.Errorf("organization unit id is required")
	}
	if item.Status == "" {
		item.Status = identitymodel.IdentityStatusActive
	}
	ancestors, _ := json.Marshal(item.AncestorIDs)
	insert := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_organization_units", workspace.String()).
		Columns("id", "code", "name", "sibling_key", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at").
		Values(item.ID, item.Code, item.Name, identitymodel.IdentityOrganizationUnitSiblingKey(item.ParentID, item.Name), string(item.NodeType), nullablePointer(item.ParentID), item.Path, string(ancestors), item.Depth, item.SortOrder, string(item.Status), s.now(), s.now())
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "code", "name", "sibling_key", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity organization unit upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *Store) UpsertManyWithinDataScope(ctx context.Context, workspaceID string, items []identitymodel.IdentityOrganizationUnit, scope identitymodel.IdentityDataScopeFilter) (bool, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	for _, item := range items {
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" {
			return false, fmt.Errorf("organization unit id is required")
		}
		exists, allowed, persistedParentID, err := s.scopedMutationCandidate(ctx, tx, workspace.String(), item.ID, scope)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
		if !scope.Unrestricted {
			parentID := ""
			if item.ParentID != nil {
				parentID = strings.TrimSpace(*item.ParentID)
			}
			parentChanged := !exists || parentID != persistedParentID
			if parentChanged && (parentID == "" || !organizationUnitIDInScope(scope, parentID)) {
				return false, nil
			}
		}
		if exists {
			if err := s.updateWithinDataScope(ctx, tx, workspace.String(), item, scope); err != nil {
				return false, err
			}
			continue
		}
		if err := s.insert(ctx, tx, workspace.String(), item); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) scopedMutationCandidate(ctx context.Context, tx *sql.Tx, workspaceID, organizationUnitID string, scope identitymodel.IdentityDataScopeFilter) (exists bool, allowed bool, parentID string, err error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_organization_units", workspaceID).
		Columns("id", "parent_id").Where(query.Equal("id", organizationUnitID)).Build()
	if err != nil {
		return false, false, "", fmt.Errorf("build identity organization unit mutation candidate query: %w", err)
	}
	var id string
	var persistedParentID sql.NullString
	err = tx.QueryRowContext(ctx, statement, arguments...).Scan(&id, &persistedParentID)
	if err == sql.ErrNoRows {
		// A new unit is authorized by its persisted parent below; its fresh ID
		// cannot already be present in the Principal's cached organization tree.
		return false, true, "", nil
	}
	if err != nil {
		return false, false, "", err
	}
	return true, scope.Unrestricted || organizationUnitIDInScope(scope, organizationUnitID), persistedParentID.String, nil
}

func (s *Store) updateWithinDataScope(ctx context.Context, tx *sql.Tx, workspaceID string, item identitymodel.IdentityOrganizationUnit, scope identitymodel.IdentityDataScopeFilter) error {
	ancestors, _ := json.Marshal(item.AncestorIDs)
	predicates := []query.Predicate{query.Equal("id", item.ID)}
	if !scope.Unrestricted {
		predicates = append(predicates, organizationUnitDataScopePredicate(scope))
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.backend.SQLRenderer(), "_identity_organization_units", workspaceID).
		Set("code", item.Code).Set("name", item.Name).Set("sibling_key", identitymodel.IdentityOrganizationUnitSiblingKey(item.ParentID, item.Name)).Set("node_type", string(item.NodeType)).
		Set("parent_id", nullablePointer(item.ParentID)).Set("path", item.Path).Set("ancestor_ids", string(ancestors)).
		Set("depth", item.Depth).Set("sort_order", item.SortOrder).Set("status", string(item.Status)).Set("updated_at", s.now()).
		Where(query.And(predicates...)).Build()
	if err != nil {
		return fmt.Errorf("build scoped identity organization unit update: %w", err)
	}
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("identity organization unit scope changed during update")
	}
	return nil
}

func (s *Store) insert(ctx context.Context, tx *sql.Tx, workspaceID string, item identitymodel.IdentityOrganizationUnit) error {
	ancestors, _ := json.Marshal(item.AncestorIDs)
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_organization_units", workspaceID).
		Columns("id", "code", "name", "sibling_key", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status", "created_at", "updated_at").
		Values(item.ID, item.Code, item.Name, identitymodel.IdentityOrganizationUnitSiblingKey(item.ParentID, item.Name), string(item.NodeType), nullablePointer(item.ParentID), item.Path, string(ancestors), item.Depth, item.SortOrder, string(item.Status), s.now(), s.now()).
		Build()
	if err != nil {
		return fmt.Errorf("build scoped identity organization unit insert: %w", err)
	}
	_, err = tx.ExecContext(ctx, statement, arguments...)
	return err
}

func organizationUnitIDInScope(scope identitymodel.IdentityDataScopeFilter, id string) bool {
	id = strings.TrimSpace(id)
	for _, allowedID := range scope.Normalized().OwnerOrgIDs {
		if allowedID == id {
			return true
		}
	}
	return false
}

func (s *Store) List(ctx context.Context, workspaceID string) ([]identitymodel.IdentityOrganizationUnit, error) {
	return s.ListWithinDataScope(ctx, workspaceID, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
}

func (s *Store) ListWithinDataScope(ctx context.Context, workspaceID string, scope identitymodel.IdentityDataScopeFilter) ([]identitymodel.IdentityOrganizationUnit, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_organization_units", workspace.String()).
		Columns("id", "code", "name", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status").
		OrderBy(query.Ascending("depth"), query.Ascending("parent_id"), query.Ascending("sort_order"), query.Ascending("id"))
	if !scope.Unrestricted {
		builder.Where(organizationUnitDataScopePredicate(scope))
	}
	statement, arguments, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build identity organization units query: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityOrganizationUnit{}
	for rows.Next() {
		var item identitymodel.IdentityOrganizationUnit
		var parentID sql.NullString
		var nodeType string
		var ancestors string
		if err := rows.Scan(&item.ID, &item.Code, &item.Name, &nodeType, &parentID, &item.Path, &ancestors, &item.Depth, &item.SortOrder, &item.Status); err != nil {
			return nil, err
		}
		if parentID.Valid {
			value := parentID.String
			item.ParentID = &value
		}
		item.NodeType = identitymodel.IdentityOrganizationUnitType(nodeType)
		_ = json.Unmarshal([]byte(ancestors), &item.AncestorIDs)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetWithinDataScope(ctx context.Context, workspaceID, organizationUnitID string, scope identitymodel.IdentityDataScopeFilter) (identitymodel.IdentityOrganizationUnit, bool, error) {
	workspace, err := identitymodel.NewWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, err
	}
	predicates := []query.Predicate{query.Equal("id", strings.TrimSpace(organizationUnitID))}
	if !scope.Unrestricted {
		predicates = append(predicates, organizationUnitDataScopePredicate(scope))
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.backend.SQLRenderer(), "_identity_organization_units", workspace.String()).
		Columns("id", "code", "name", "node_type", "parent_id", "path", "ancestor_ids", "depth", "sort_order", "status").
		Where(query.And(predicates...)).
		Build()
	if err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, fmt.Errorf("build scoped identity organization unit query: %w", err)
	}
	var item identitymodel.IdentityOrganizationUnit
	var parentID sql.NullString
	var nodeType, ancestors string
	err = s.backend.QueryIdentityRowContext(ctx, statement, arguments...).Scan(&item.ID, &item.Code, &item.Name, &nodeType, &parentID, &item.Path, &ancestors, &item.Depth, &item.SortOrder, &item.Status)
	if err == sql.ErrNoRows {
		return identitymodel.IdentityOrganizationUnit{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityOrganizationUnit{}, false, err
	}
	if parentID.Valid {
		value := parentID.String
		item.ParentID = &value
	}
	item.NodeType = identitymodel.IdentityOrganizationUnitType(nodeType)
	_ = json.Unmarshal([]byte(ancestors), &item.AncestorIDs)
	return item, true, nil
}

func organizationUnitDataScopePredicate(scope identitymodel.IdentityDataScopeFilter) query.Predicate {
	scope = scope.Normalized()
	if scope.Unrestricted {
		return query.AlwaysTrue()
	}
	if len(scope.OwnerOrgIDs) == 0 {
		return query.AlwaysFalse()
	}
	values := make([]any, len(scope.OwnerOrgIDs))
	for index := range scope.OwnerOrgIDs {
		values[index] = scope.OwnerOrgIDs[index]
	}
	return query.In("id", values...)
}

func nullablePointer(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return *value
}
