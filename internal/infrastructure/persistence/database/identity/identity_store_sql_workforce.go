package identity

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

var identityWorkforceProfileColumns = []string{"id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version"}
var identityWorkforceAssignmentColumns = []string{"id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version"}

func (s *SQLIdentityStore) ListIdentityWorkforceProfiles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityWorkforceProfile, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	statement, arguments, err := identityWorkforceProfileSelect(s, workspaceID).OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity workforce profiles query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityWorkforceProfile{}
	for rows.Next() {
		profile, scanErr := scanIdentityWorkforceProfile(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, profile)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) GetIdentityWorkforceProfile(ctx context.Context, workspaceID, profileID string) (identitymodel.IdentityWorkforceProfile, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, err
	}
	statement, arguments, err := identityWorkforceProfileSelect(s, workspaceID).Where(ormbuilder.Equal("id", profileID)).Build()
	if err != nil {
		return identitymodel.IdentityWorkforceProfile{}, false, fmt.Errorf("build identity workforce profile query: %w", err)
	}
	row := s.reader(ctx).QueryRowContext(ctx, statement, arguments...)
	profile, err := scanIdentityWorkforceProfile(row)
	if err == sql.ErrNoRows {
		return identitymodel.IdentityWorkforceProfile{}, false, nil
	}
	return profile, err == nil, err
}

func (s *SQLIdentityStore) UpsertIdentityWorkforceProfile(ctx context.Context, workspaceID string, profile identitymodel.IdentityWorkforceProfile) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if profile.ID == "" {
		return fmt.Errorf("workforce profile id is required")
	}
	if profile.Version == 0 {
		profile.Version = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.writeIdentityWorkforceProfile(ctx, tx, workspaceID, profile); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) writeIdentityWorkforceProfile(ctx context.Context, execer identityUserExecer, workspaceID string, profile identitymodel.IdentityWorkforceProfile) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if profile.ID == "" {
		return fmt.Errorf("workforce profile id is required")
	}
	if profile.Version == 0 {
		profile.Version = 1
	}
	now := nowString()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_workforce_profiles", workspaceID).
		Columns("id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "created_at", "updated_at").
		Values(profile.ID, profile.OrganizationID, profile.IdentityUserID, profile.WorkerNo, string(profile.WorkerType), string(profile.WorkStatus), nullIfBlank(profile.StartDate), nullIfBlank(profile.EndDate), nullIfBlank(profile.PrimaryAssignmentID), profile.Version, now, now)
	s.engineProfile().ApplyUpsert(insert, []string{"workspace_id", "id"}, "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity workforce profile upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func (s *SQLIdentityStore) ListIdentityWorkforceAssignments(ctx context.Context, workspaceID, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	builder := identityWorkforceAssignmentSelect(s, workspaceID)
	if profileID != "" {
		builder.Where(ormbuilder.Equal("workforce_profile_id", profileID))
	}
	statement, arguments, err := builder.OrderBy(ormbuilder.Ascending("id")).Build()
	if err != nil {
		return nil, fmt.Errorf("build identity workforce assignments query: %w", err)
	}
	rows, err := s.reader(ctx).QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identitymodel.IdentityWorkforceAssignment{}
	for rows.Next() {
		assignment, scanErr := scanIdentityWorkforceAssignment(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, assignment)
	}
	return out, rows.Err()
}

func (s *SQLIdentityStore) GetIdentityWorkforceAssignment(ctx context.Context, workspaceID, assignmentID string) (identitymodel.IdentityWorkforceAssignment, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkforceAssignment{}, false, err
	}
	statement, arguments, err := identityWorkforceAssignmentSelect(s, workspaceID).Where(ormbuilder.Equal("id", assignmentID)).Build()
	if err != nil {
		return identitymodel.IdentityWorkforceAssignment{}, false, fmt.Errorf("build identity workforce assignment query: %w", err)
	}
	row := s.reader(ctx).QueryRowContext(ctx, statement, arguments...)
	assignment, err := scanIdentityWorkforceAssignment(row)
	if err == sql.ErrNoRows {
		return identitymodel.IdentityWorkforceAssignment{}, false, nil
	}
	return assignment, err == nil, err
}

func (s *SQLIdentityStore) UpsertIdentityWorkforceAssignment(ctx context.Context, workspaceID string, assignment identitymodel.IdentityWorkforceAssignment) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if assignment.ID == "" {
		return fmt.Errorf("workforce assignment id is required")
	}
	if assignment.Version == 0 {
		assignment.Version = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.writeIdentityWorkforceAssignment(ctx, tx, workspaceID, assignment); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLIdentityStore) writeIdentityWorkforceAssignment(ctx context.Context, execer identityUserExecer, workspaceID string, assignment identitymodel.IdentityWorkforceAssignment) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if assignment.ID == "" {
		return fmt.Errorf("workforce assignment id is required")
	}
	if assignment.Version == 0 {
		assignment.Version = 1
	}
	now := nowString()
	insert := ormbuilder.NewWorkspaceInsertBuilder(s.sqlRenderer(), "identity_workforce_assignments", workspaceID).
		Columns("id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "created_at", "updated_at").
		Values(assignment.ID, assignment.WorkforceProfileID, assignment.OrganizationUnitID, nullIfBlank(assignment.PositionID), nullIfBlank(assignment.ManagerWorkforceProfileID), string(assignment.AssignmentType), nullIfBlank(assignment.EffectiveFrom), nullIfBlank(assignment.EffectiveTo), string(assignment.Status), assignment.Version, now, now)
	s.engineProfile().ApplyUpsert(insert, []string{"workspace_id", "id"}, "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "updated_at")
	statement, arguments, err := insert.Build()
	if err != nil {
		return fmt.Errorf("build identity workforce assignment upsert: %w", err)
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func identityWorkforceProfileSelect(s *SQLIdentityStore, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_workforce_profiles", workspaceID).Columns(identityWorkforceProfileColumns...)
}

func identityWorkforceAssignmentSelect(s *SQLIdentityStore, workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(s.sqlRenderer(), "identity_workforce_assignments", workspaceID).Columns(identityWorkforceAssignmentColumns...)
}

type identityWorkforceScanner interface {
	Scan(...any) error
}

func scanIdentityWorkforceProfile(scanner identityWorkforceScanner) (identitymodel.IdentityWorkforceProfile, error) {
	var profile identitymodel.IdentityWorkforceProfile
	var workerType, workStatus string
	var startDate, endDate, primaryAssignmentID sql.NullString
	err := scanner.Scan(&profile.ID, &profile.OrganizationID, &profile.IdentityUserID, &profile.WorkerNo, &workerType, &workStatus, &startDate, &endDate, &primaryAssignmentID, &profile.Version)
	profile.WorkerType = identitymodel.IdentityWorkerType(workerType)
	profile.WorkStatus = identitymodel.IdentityWorkStatus(workStatus)
	profile.StartDate, profile.EndDate, profile.PrimaryAssignmentID = startDate.String, endDate.String, primaryAssignmentID.String
	return profile, err
}

func scanIdentityWorkforceAssignment(scanner identityWorkforceScanner) (identitymodel.IdentityWorkforceAssignment, error) {
	var assignment identitymodel.IdentityWorkforceAssignment
	var positionID, managerID, effectiveFrom, effectiveTo sql.NullString
	var assignmentType, status string
	err := scanner.Scan(&assignment.ID, &assignment.WorkforceProfileID, &assignment.OrganizationUnitID, &positionID, &managerID, &assignmentType, &effectiveFrom, &effectiveTo, &status, &assignment.Version)
	assignment.PositionID, assignment.ManagerWorkforceProfileID = positionID.String, managerID.String
	assignment.EffectiveFrom, assignment.EffectiveTo = effectiveFrom.String, effectiveTo.String
	assignment.AssignmentType = identitymodel.IdentityWorkforceAssignmentType(assignmentType)
	assignment.Status = identitymodel.IdentityStatus(status)
	return assignment, err
}

func nullIfBlank(value string) any {
	if value == "" {
		return nil
	}
	return value
}
