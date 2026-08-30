package core

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

var profileColumns = []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"}
var assignmentColumns = []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version"}

type Backend interface {
	DB() *sql.DB
	SQLRenderer() ormdialect.Renderer
	ApplyUpsert(*ormbuilder.InsertBuilder, []string, ...string) *ormbuilder.InsertBuilder
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

func (s *Store) ListProfiles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityWorkforceProfile, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := profileSelect(s.backend.SQLRenderer(), workspaceID).OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity workforce profiles query: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityWorkforceProfile{}
	for rows.Next() {
		item, scanErr := scanProfile(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
func (s *Store) GetProfile(ctx context.Context, workspaceID, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, err
	}
	statement, arguments, err := profileSelect(s.backend.SQLRenderer(), workspaceID).Where(ormbuilder.Equal("id", profileID)).Build()
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, fmt.Errorf("build identity workforce profile query: %w", err)
	}
	item, err := scanProfile(s.backend.QueryIdentityRowContext(ctx, statement, arguments...))
	if err == sql.ErrNoRows {
		return identitymodel.IdentityWorkforceProfile{}, false, nil
	}
	return item, err == nil, err
}
func (s *Store) UpsertProfileAtomically(ctx context.Context, workspaceID string, item identitymodel.IdentityWorkforceProfile) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.UpsertProfile(ctx, tx, workspaceID, item); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) UpsertProfile(ctx context.Context, execer Execer, workspaceID string, item identitymodel.IdentityWorkforceProfile) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	if item.ID == "" {
		return fmt.Errorf("workforce profile id is required")
	}
	if item.Version == 0 {
		item.Version = 1
	}
	now := s.now()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_workforce_profiles", workspaceID).Columns("id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "created_at", "updated_at").Values(item.ID, item.OrganizationID, item.IdentityUserID, item.WorkerNo, string(item.WorkerType), string(item.WorkStatus), nullable(item.StartDate), nullable(item.EndDate), nullable(item.PrimaryAssignmentID), item.Version, now, now)
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity workforce profile upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}
func (s *Store) ListAssignments(ctx context.Context, workspaceID, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := assignmentSelect(s.backend.SQLRenderer(), workspaceID)
	if profileID != "" {
		builder.Where(ormbuilder.Equal("workforce_profile_id", profileID))
	}
	statement, arguments, err := builder.OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity workforce assignments query: %w", err)
	}
	rows, err := s.backend.QueryIdentityContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityWorkforceAssignment{}
	for rows.Next() {
		item, scanErr := scanAssignment(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
func (s *Store) GetAssignment(ctx context.Context, workspaceID, assignmentID string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceAssignment{}, false, err
	}
	statement, arguments, err := assignmentSelect(s.backend.SQLRenderer(), workspaceID).Where(ormbuilder.Equal("id", assignmentID)).Build()
	if err != nil {
		return identitymodel.IdentityWorkforceAssignment{}, false, fmt.Errorf("build identity workforce assignment query: %w", err)
	}
	item, err := scanAssignment(s.backend.QueryIdentityRowContext(ctx, statement, arguments...))
	if err == sql.ErrNoRows {
		return identitymodel.IdentityWorkforceAssignment{}, false, nil
	}
	return item, err == nil, err
}
func (s *Store) UpsertAssignmentAtomically(ctx context.Context, workspaceID string, item identitymodel.IdentityWorkforceAssignment) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	tx, err := s.backend.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.UpsertAssignment(ctx, tx, workspaceID, item); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) UpsertAssignment(ctx context.Context, execer Execer, workspaceID string, item identitymodel.IdentityWorkforceAssignment) error {
	workspaceID, err := workspace(workspaceID)
	if err != nil {
		return err
	}
	if item.ID == "" {
		return fmt.Errorf("workforce assignment id is required")
	}
	if item.Version == 0 {
		item.Version = 1
	}
	now := s.now()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.backend.SQLRenderer(), "_identity_workforce_assignments", workspaceID).Columns("id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "created_at", "updated_at").Values(item.ID, item.WorkforceProfileID, item.OrganizationUnitID, nullable(item.PositionID), nullable(item.ManagerWorkforceProfileID), string(item.AssignmentType), nullable(item.EffectiveFrom), nullable(item.EffectiveTo), string(item.Status), item.Version, now, now)
	s.backend.ApplyUpsert(insert, []string{"workspace_id", "id"}, "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity workforce assignment upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func profileSelect(renderer ormdialect.Renderer, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(renderer, "_identity_workforce_profiles", workspaceID).Columns(profileColumns...)
}
func assignmentSelect(renderer ormdialect.Renderer, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(renderer, "_identity_workforce_assignments", workspaceID).Columns(assignmentColumns...)
}

type scanner interface{ Scan(...any) error }

func scanProfile(row scanner) (identitymodel.IdentityWorkforceProfile, error) {
	var item identitymodel.IdentityWorkforceProfile
	var workerType, workStatus string
	var startDate, endDate, primaryAssignmentID sql.NullString
	err := row.Scan(&item.ID, &item.OrganizationID, &item.IdentityUserID, &item.WorkerNo, &workerType, &workStatus, &startDate, &endDate, &primaryAssignmentID, &item.Version)
	item.WorkerType, item.WorkStatus = identitymodel.IdentityWorkerType(workerType), identitymodel.IdentityWorkStatus(workStatus)
	item.StartDate, item.EndDate, item.PrimaryAssignmentID = startDate.String, endDate.String, primaryAssignmentID.String
	return item, err
}
func scanAssignment(row scanner) (identitymodel.IdentityWorkforceAssignment, error) {
	var item identitymodel.IdentityWorkforceAssignment
	var positionID, managerID, effectiveFrom, effectiveTo sql.NullString
	var assignmentType, status string
	err := row.Scan(&item.ID, &item.WorkforceProfileID, &item.OrganizationUnitID, &positionID, &managerID, &assignmentType, &effectiveFrom, &effectiveTo, &status, &item.Version)
	item.PositionID, item.ManagerWorkforceProfileID, item.EffectiveFrom, item.EffectiveTo = positionID.String, managerID.String, effectiveFrom.String, effectiveTo.String
	item.AssignmentType, item.Status = identitymodel.IdentityWorkforceAssignmentType(assignmentType), identitymodel.IdentityStatus(status)
	return item, err
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func workspace(value string) (string, error) {
	id, err := identitymodel.NewWorkspaceID(value)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
