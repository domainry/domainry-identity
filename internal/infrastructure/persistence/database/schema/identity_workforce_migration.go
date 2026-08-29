package schema

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var legacyIdentityUserWorkforceColumns = []string{
	"employee_no",
	"gender",
	"hire_date",
	"job_title",
	"job_level",
	"employment_type",
	"employment_status",
	"department_id",
	"department_path",
	"manager_id",
	"manager_path",
	"manager_ancestor_ids",
	"manager_depth",
}

var legacyIdentityUserWorkforceIndexes = []string{
	"idx_identity_users_department",
	"idx_identity_users_manager",
	"idx_identity_users_manager_path",
}

type legacyIdentityUserWorkforceFacts struct {
	UserID             string `json:"identity_user_id"`
	WorkspaceID        string `json:"workspace_id"`
	EmployeeNo         string `json:"employee_no,omitempty"`
	Gender             string `json:"gender,omitempty"`
	HireDate           string `json:"hire_date,omitempty"`
	JobTitle           string `json:"job_title,omitempty"`
	JobLevel           string `json:"job_level,omitempty"`
	EmploymentType     string `json:"employment_type,omitempty"`
	EmploymentStatus   string `json:"employment_status,omitempty"`
	DepartmentID       string `json:"department_id,omitempty"`
	DepartmentPath     string `json:"department_path,omitempty"`
	ManagerID          string `json:"manager_id,omitempty"`
	ManagerPath        string `json:"manager_path,omitempty"`
	ManagerAncestorIDs string `json:"manager_ancestor_ids,omitempty"`
	ManagerDepth       string `json:"manager_depth,omitempty"`
}

type legacyIdentityUserWorkforceTarget struct {
	profileID    string
	assignmentID string
}

func migrateLegacyIdentityUserWorkforceFacts(ctx context.Context, store Store) error {
	columns, err := store.TableColumns(ctx, "identity_users")
	if err != nil {
		return fmt.Errorf("inspect identity_users for workforce migration: %w", err)
	}
	if !columns["employee_no"] && !columns["department_id"] && !columns["manager_id"] {
		return nil
	}
	facts, err := loadLegacyIdentityUserWorkforceFacts(ctx, store, columns)
	if err != nil {
		return err
	}
	if err := persistLegacyIdentityUserWorkforceFacts(ctx, store, facts); err != nil {
		return err
	}
	if err := dropLegacyIdentityUserWorkforceIndexes(ctx, store); err != nil {
		return err
	}
	for _, column := range legacyIdentityUserWorkforceColumns {
		if !columns[column] {
			continue
		}
		query := "ALTER TABLE " + store.TableIdentifier("identity_users") + " DROP COLUMN " + store.Identifier(column)
		if _, err := store.SchemaDB().ExecContext(ctx, query); err != nil {
			return fmt.Errorf("drop migrated identity_users.%s: %w", column, err)
		}
	}
	return nil
}

func loadLegacyIdentityUserWorkforceFacts(ctx context.Context, store Store, columns map[string]bool) ([]legacyIdentityUserWorkforceFacts, error) {
	selected := []string{store.Identifier("id"), store.Identifier("workspace_id")}
	for _, column := range legacyIdentityUserWorkforceColumns {
		if columns[column] {
			selected = append(selected, "COALESCE("+store.Identifier(column)+", '')")
		} else {
			selected = append(selected, "''")
		}
	}
	rows, err := store.SchemaDB().QueryContext(ctx, "SELECT "+strings.Join(selected, ", ")+" FROM "+store.TableIdentifier("identity_users")+" ORDER BY "+store.Identifier("workspace_id")+", "+store.Identifier("id"))
	if err != nil {
		return nil, fmt.Errorf("read legacy identity workforce facts: %w", err)
	}
	defer rows.Close()
	facts := []legacyIdentityUserWorkforceFacts{}
	for rows.Next() {
		values := make([]any, len(selected))
		destinations := make([]any, len(selected))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, fmt.Errorf("scan legacy identity workforce facts: %w", err)
		}
		text := make([]string, len(values))
		for index := range values {
			text[index] = identityMigrationString(values[index])
		}
		facts = append(facts, legacyIdentityUserWorkforceFacts{
			UserID: text[0], WorkspaceID: text[1], EmployeeNo: text[2], Gender: text[3],
			HireDate: text[4], JobTitle: text[5], JobLevel: text[6], EmploymentType: text[7],
			EmploymentStatus: text[8], DepartmentID: text[9], DepartmentPath: text[10],
			ManagerID: text[11], ManagerPath: text[12], ManagerAncestorIDs: text[13], ManagerDepth: text[14],
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate legacy identity workforce facts: %w", err)
	}
	return facts, nil
}

func persistLegacyIdentityUserWorkforceFacts(ctx context.Context, store Store, facts []legacyIdentityUserWorkforceFacts) error {
	tx, err := store.SchemaDB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin identity workforce migration: %w", err)
	}
	defer tx.Rollback()
	targets := make(map[string]legacyIdentityUserWorkforceTarget, len(facts))
	for _, fact := range facts {
		target, err := ensureLegacyWorkforceProfile(ctx, tx, store, fact)
		if err != nil {
			return err
		}
		targets[identityMigrationUserKey(fact.WorkspaceID, fact.UserID)] = target
	}
	for _, fact := range facts {
		key := identityMigrationUserKey(fact.WorkspaceID, fact.UserID)
		target := targets[key]
		if identityMigrationNeedsAssignment(fact) {
			managerProfileID := ""
			if manager, ok := targets[identityMigrationUserKey(fact.WorkspaceID, fact.ManagerID)]; ok {
				managerProfileID = manager.profileID
			}
			assignmentID, err := ensureLegacyWorkforceAssignment(ctx, tx, store, fact, target.profileID, managerProfileID)
			if err != nil {
				return err
			}
			target.assignmentID = assignmentID
			targets[key] = target
		}
		if err := ensureLegacyWorkforceMigrationReceipt(ctx, tx, store, fact, target); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit identity workforce migration: %w", err)
	}
	return nil
}

func ensureLegacyWorkforceProfile(ctx context.Context, tx *sql.Tx, store Store, fact legacyIdentityUserWorkforceFacts) (legacyIdentityUserWorkforceTarget, error) {
	var profileID string
	query := "SELECT " + store.Identifier("id") + " FROM " + store.TableIdentifier("identity_workforce_profiles") +
		" WHERE " + store.Identifier("workspace_id") + " = " + store.Placeholder(1) +
		" AND " + store.Identifier("identity_user_id") + " = " + store.Placeholder(2) +
		" ORDER BY " + store.Identifier("id")
	err := tx.QueryRowContext(ctx, query, fact.WorkspaceID, fact.UserID).Scan(&profileID)
	if err == nil {
		return legacyIdentityUserWorkforceTarget{profileID: profileID}, nil
	}
	if err != sql.ErrNoRows {
		return legacyIdentityUserWorkforceTarget{}, fmt.Errorf("find migrated workforce profile for %s: %w", fact.UserID, err)
	}
	profileID = identityMigrationID("workforce-profile", fact.WorkspaceID, fact.UserID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	columns := identityMigrationIdentifiers(store, "id", "workspace_id", "organization_id", "identity_user_id", "worker_no", "worker_type", "work_status", "start_date", "end_date", "primary_assignment_id", "version", "created_at", "updated_at")
	insert := "INSERT INTO " + store.TableIdentifier("identity_workforce_profiles") + " (" + columns + ") VALUES (" + identityMigrationPlaceholders(store, 13) + ")"
	if _, err := tx.ExecContext(ctx, insert,
		profileID, fact.WorkspaceID, fact.WorkspaceID, fact.UserID, identityMigrationWorkerNo(fact),
		identityMigrationWorkerType(fact.EmploymentType), identityMigrationWorkStatus(fact.EmploymentStatus),
		identityMigrationNullable(fact.HireDate), nil, nil, 1, now, now,
	); err != nil {
		return legacyIdentityUserWorkforceTarget{}, fmt.Errorf("create migrated workforce profile for %s: %w", fact.UserID, err)
	}
	return legacyIdentityUserWorkforceTarget{profileID: profileID}, nil
}

func ensureLegacyWorkforceAssignment(ctx context.Context, tx *sql.Tx, store Store, fact legacyIdentityUserWorkforceFacts, profileID, managerProfileID string) (string, error) {
	assignmentID := identityMigrationID("workforce-assignment", fact.WorkspaceID, fact.UserID)
	var existingID string
	query := "SELECT " + store.Identifier("id") + " FROM " + store.TableIdentifier("identity_workforce_assignments") +
		" WHERE " + store.Identifier("workspace_id") + " = " + store.Placeholder(1) +
		" AND " + store.Identifier("id") + " = " + store.Placeholder(2)
	err := tx.QueryRowContext(ctx, query, fact.WorkspaceID, assignmentID).Scan(&existingID)
	if err == nil {
		return existingID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("find migrated workforce assignment for %s: %w", fact.UserID, err)
	}
	unitID := strings.TrimSpace(fact.DepartmentID)
	if unitID == "" {
		unitID = identityMigrationID("unassigned-organization-unit", fact.WorkspaceID)
	}
	positionID := ""
	if strings.TrimSpace(fact.JobTitle) != "" || strings.TrimSpace(fact.JobLevel) != "" {
		positionID = identityMigrationID("legacy-position", fact.WorkspaceID, fact.JobTitle, fact.JobLevel)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	columns := identityMigrationIdentifiers(store, "id", "workspace_id", "workforce_profile_id", "organization_unit_id", "position_id", "manager_workforce_profile_id", "assignment_type", "effective_from", "effective_to", "status", "version", "created_at", "updated_at")
	insert := "INSERT INTO " + store.TableIdentifier("identity_workforce_assignments") + " (" + columns + ") VALUES (" + identityMigrationPlaceholders(store, 13) + ")"
	if _, err := tx.ExecContext(ctx, insert,
		assignmentID, fact.WorkspaceID, profileID, unitID, identityMigrationNullable(positionID),
		identityMigrationNullable(managerProfileID), "primary", identityMigrationNullable(fact.HireDate),
		nil, identityMigrationAssignmentStatus(fact.EmploymentStatus), 1, now, now,
	); err != nil {
		return "", fmt.Errorf("create migrated workforce assignment for %s: %w", fact.UserID, err)
	}
	update := "UPDATE " + store.TableIdentifier("identity_workforce_profiles") + " SET " + store.Identifier("primary_assignment_id") + " = " + store.Placeholder(1) + ", " + store.Identifier("updated_at") + " = " + store.Placeholder(2) +
		" WHERE " + store.Identifier("workspace_id") + " = " + store.Placeholder(3) + " AND " + store.Identifier("id") + " = " + store.Placeholder(4) +
		" AND (" + store.Identifier("primary_assignment_id") + " IS NULL OR " + store.Identifier("primary_assignment_id") + " = '')"
	if _, err := tx.ExecContext(ctx, update, assignmentID, now, fact.WorkspaceID, profileID); err != nil {
		return "", fmt.Errorf("link migrated workforce assignment for %s: %w", fact.UserID, err)
	}
	return assignmentID, nil
}

func ensureLegacyWorkforceMigrationReceipt(ctx context.Context, tx *sql.Tx, store Store, fact legacyIdentityUserWorkforceFacts, target legacyIdentityUserWorkforceTarget) error {
	var count int
	query := "SELECT COUNT(*) FROM " + store.TableIdentifier("identity_workforce_legacy_migration_receipts") +
		" WHERE " + store.Identifier("workspace_id") + " = " + store.Placeholder(1) +
		" AND " + store.Identifier("identity_user_id") + " = " + store.Placeholder(2)
	if err := tx.QueryRowContext(ctx, query, fact.WorkspaceID, fact.UserID).Scan(&count); err != nil {
		return fmt.Errorf("find identity workforce migration receipt for %s: %w", fact.UserID, err)
	}
	if count > 0 {
		return nil
	}
	// This concrete value contains only strings, so JSON encoding cannot fail.
	raw, _ := json.Marshal(fact)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	columns := identityMigrationIdentifiers(store, "id", "workspace_id", "identity_user_id", "workforce_profile_id", "workforce_assignment_id", "legacy_facts_json", "migrated_at")
	insert := "INSERT INTO " + store.TableIdentifier("identity_workforce_legacy_migration_receipts") + " (" + columns + ") VALUES (" + identityMigrationPlaceholders(store, 7) + ")"
	if _, err := tx.ExecContext(ctx, insert,
		identityMigrationID("workforce-migration-receipt", fact.WorkspaceID, fact.UserID),
		fact.WorkspaceID, fact.UserID, target.profileID, identityMigrationNullable(target.assignmentID), string(raw), now,
	); err != nil {
		return fmt.Errorf("create identity workforce migration receipt for %s: %w", fact.UserID, err)
	}
	return nil
}

func dropLegacyIdentityUserWorkforceIndexes(ctx context.Context, store Store) error {
	indexes, err := store.TableIndexes(ctx, "identity_users")
	if err != nil {
		return fmt.Errorf("inspect identity_users indexes for workforce migration: %w", err)
	}
	for _, index := range legacyIdentityUserWorkforceIndexes {
		if !indexes[index] {
			continue
		}
		if err := store.DropIndex(ctx, "identity_users", index); err != nil {
			return fmt.Errorf("drop migrated identity_users index %s: %w", index, err)
		}
	}
	return nil
}

func identityMigrationWorkerNo(fact legacyIdentityUserWorkforceFacts) string {
	if value := strings.TrimSpace(fact.EmployeeNo); value != "" {
		return value
	}
	return fact.UserID
}

func identityMigrationWorkerType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "contractor":
		return "contractor"
	case "temporary":
		return "temporary"
	default:
		return "employee"
	}
}

func identityMigrationWorkStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "terminated":
		return "terminated"
	case "on_leave", "suspended":
		return "suspended"
	case "pending":
		return "pending"
	default:
		return "active"
	}
}

func identityMigrationAssignmentStatus(value string) string {
	if identityMigrationWorkStatus(value) == "active" {
		return "active"
	}
	return "disabled"
}

func identityMigrationNeedsAssignment(fact legacyIdentityUserWorkforceFacts) bool {
	return strings.TrimSpace(fact.DepartmentID) != "" ||
		strings.TrimSpace(fact.ManagerID) != "" ||
		strings.TrimSpace(fact.JobTitle) != "" ||
		strings.TrimSpace(fact.JobLevel) != ""
}

func identityMigrationID(kind string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(append([]string{kind}, parts...), "\x00")))
	return kind + "-" + hex.EncodeToString(sum[:12])
}

func identityMigrationUserKey(workspaceID, userID string) string {
	return workspaceID + "\x00" + userID
}

func identityMigrationNullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func identityMigrationIdentifiers(store Store, columns ...string) string {
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = store.Identifier(column)
	}
	return strings.Join(quoted, ", ")
}

func identityMigrationPlaceholders(store Store, count int) string {
	out := make([]string, count)
	for index := range out {
		out[index] = store.Placeholder(index + 1)
	}
	return strings.Join(out, ", ")
}

func identityMigrationString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case []byte:
		return string(typed)
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}
