package identity

import (
	"context"
	"database/sql"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func (s *SQLIdentityStore) ListIdentityWorkforceProfiles(ctx context.Context, workspaceID string) ([]identitymodel.IdentityWorkforceProfile, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	columns := s.identityColumns("id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version")
	rows, err := s.reader(ctx).QueryContext(ctx, "SELECT "+columns+" FROM "+s.tableIdentifier("identity_workforce_profiles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" ORDER BY "+s.identifier("id"), workspaceID)
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
	columns := s.identityColumns("id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version")
	row := s.reader(ctx).QueryRowContext(ctx, "SELECT "+columns+" FROM "+s.tableIdentifier("identity_workforce_profiles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, profileID)
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
	if _, err := execer.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_workforce_profiles")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, profile.ID); err != nil {
		return err
	}
	columns := s.identityColumns("id", "workspace_id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "created_at", "updated_at")
	if _, err = execer.ExecContext(ctx, "INSERT INTO "+s.tableIdentifier("identity_workforce_profiles")+" ("+columns+") VALUES ("+s.placeholders(13)+")",
		profile.ID, workspaceID, profile.OrganizationID, profile.IdentityUserID, profile.WorkerNo, string(profile.WorkerType), string(profile.WorkStatus),
		nullIfBlank(profile.StartDate), nullIfBlank(profile.EndDate), nullIfBlank(profile.PrimaryAssignmentID), profile.Version, nowString(), nowString()); err != nil {
		return err
	}
	return nil
}

func (s *SQLIdentityStore) ListIdentityWorkforceAssignments(ctx context.Context, workspaceID, profileID string) ([]identitymodel.IdentityWorkforceAssignment, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, err
	}
	columns := s.identityColumns("id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version")
	query := "SELECT " + columns + " FROM " + s.tableIdentifier("identity_workforce_assignments") + " WHERE " + s.identifier("workspace_id") + " = " + s.placeholder(1)
	args := []any{workspaceID}
	if profileID != "" {
		query += " AND " + s.identifier("workforce_profile_id") + " = " + s.placeholder(2)
		args = append(args, profileID)
	}
	query += " ORDER BY " + s.identifier("id")
	rows, err := s.reader(ctx).QueryContext(ctx, query, args...)
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
	columns := s.identityColumns("id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version")
	row := s.reader(ctx).QueryRowContext(ctx, "SELECT "+columns+" FROM "+s.tableIdentifier("identity_workforce_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, assignmentID)
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
	if _, err := execer.ExecContext(ctx, "DELETE FROM "+s.tableIdentifier("identity_workforce_assignments")+" WHERE "+s.identifier("workspace_id")+" = "+s.placeholder(1)+" AND "+s.identifier("id")+" = "+s.placeholder(2), workspaceID, assignment.ID); err != nil {
		return err
	}
	columns := s.identityColumns("id", "workspace_id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "created_at", "updated_at")
	if _, err = execer.ExecContext(ctx, "INSERT INTO "+s.tableIdentifier("identity_workforce_assignments")+" ("+columns+") VALUES ("+s.placeholders(13)+")",
		assignment.ID, workspaceID, assignment.WorkforceProfileID, assignment.OrganizationUnitID, nullIfBlank(assignment.PositionID),
		nullIfBlank(assignment.ManagerWorkforceProfileID), string(assignment.AssignmentType), nullIfBlank(assignment.EffectiveFrom),
		nullIfBlank(assignment.EffectiveTo), string(assignment.Status), assignment.Version, nowString(), nowString()); err != nil {
		return err
	}
	return nil
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
