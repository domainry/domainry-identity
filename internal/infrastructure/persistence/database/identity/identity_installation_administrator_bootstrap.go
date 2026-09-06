package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-orm/query"
)

const installationAdministratorRoleKey = "tenant_admin"

type InstallationAdministratorBootstrapReceipt struct {
	ID                    string
	WorkspaceID           string
	InvocationID          string
	RequestFingerprint    string
	ContractVersion       string
	ContractHash          string
	UserID                string
	LoginID               string
	CredentialClaimedAt   string
	CredentialDeliveredAt string
	CreatedAt             string
}

func InstallationAdministratorBootstrapReceiptID(workspaceID, invocationID string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(workspaceID) + "\x00installation_administrator_bootstrap_v1\x00" + strings.TrimSpace(invocationID)))
	return "installation_admin_" + hex.EncodeToString(digest[:16])
}

func (s *SQLIdentityStore) GetInstallationAdministratorBootstrapReceiptWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID, invocationID string) (InstallationAdministratorBootstrapReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_installation_administrator_bootstrap_receipts", workspaceID).
		Columns("id", "invocation_id", "request_fingerprint", "contract_version", "contract_hash", "user_id", "login_id", "credential_claimed_at", "credential_delivered_at", "created_at").
		Where(query.Equal("invocation_id", strings.TrimSpace(invocationID))).Limit(1).Build()
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	receipt, err := scanInstallationAdministratorBootstrapReceipt(execer.QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return InstallationAdministratorBootstrapReceipt{}, false, nil
	}
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	receipt.WorkspaceID = workspaceID
	return receipt, true, nil
}

func (s *SQLIdentityStore) InstallationAdministratorBootstrapStateWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID, loginID string) (companyID string, occupied bool, err error) {
	workspaceID, err = identityWorkspaceID(workspaceID)
	if err != nil {
		return "", false, err
	}
	roleID := WorkspaceRoleID(workspaceID, installationAdministratorRoleKey)
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_roles", workspaceID).
		Columns("id").Where(query.And(query.Equal("id", roleID), query.Equal("role_key", installationAdministratorRoleKey), query.Equal("status", "active"))).Limit(1).Build()
	if err != nil {
		return "", false, err
	}
	if err := execer.QueryRowContext(ctx, statement, arguments...).Scan(&roleID); errors.Is(err, sql.ErrNoRows) {
		return "", false, fmt.Errorf("installation administrator role is unavailable")
	} else if err != nil {
		return "", false, err
	}
	companyPredicate := query.And(query.Equal("node_type", "company"), query.Equal("status", "active"))
	statement, arguments, err = query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Projections(query.Project(query.CountAll())).Where(companyPredicate).Build()
	if err != nil {
		return "", false, err
	}
	var companies int
	if err := execer.QueryRowContext(ctx, statement, arguments...).Scan(&companies); err != nil {
		return "", false, err
	}
	if companies != 1 {
		return "", false, fmt.Errorf("installation Workspace must have exactly one active company")
	}
	statement, arguments, err = query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_organization_units", workspaceID).
		Columns("id").Where(companyPredicate).Limit(1).Build()
	if err != nil {
		return "", false, err
	}
	if err := execer.QueryRowContext(ctx, statement, arguments...).Scan(&companyID); err != nil {
		return "", false, err
	}
	for _, lookup := range []struct {
		table     string
		predicate query.Predicate
	}{
		{table: "_identity_user_role_assignments", predicate: query.And(query.Equal("role_id", roleID), query.Equal("status", "active"))},
		{table: "_identity_users", predicate: query.Equal("email", strings.ToLower(strings.TrimSpace(loginID)))},
	} {
		statement, arguments, err = query.NewWorkspaceSelectBuilder(s.sqlRenderer(), lookup.table, workspaceID).
			Projections(query.Project(query.CountAll())).Where(lookup.predicate).Build()
		if err != nil {
			return "", false, err
		}
		var count int
		if err := execer.QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
			return "", false, err
		}
		if count != 0 {
			return "", true, nil
		}
	}
	return strings.TrimSpace(companyID), false, nil
}

func (s *SQLIdentityStore) InsertInstallationAdministratorWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string, user identitymodel.IdentityUser, receipt InstallationAdministratorBootstrapReceipt) error {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return err
	}
	if err := s.userStore().CreateWithExecutor(ctx, execer, workspaceID, user); err != nil {
		return fmt.Errorf("create installation administrator: %w", err)
	}
	if err := s.writeIdentityUserRoleAssignment(ctx, execer, workspaceID, identitymodel.IdentityUserRoleAssignment{
		UserID: user.ID, RoleID: WorkspaceRoleID(workspaceID, installationAdministratorRoleKey),
		Source: "installation_administrator_bootstrap_v1", Status: "active",
	}); err != nil {
		return fmt.Errorf("assign installation administrator role: %w", err)
	}
	receipt.WorkspaceID = workspaceID
	if receipt.CreatedAt == "" {
		receipt.CreatedAt = nowString()
	}
	statement, arguments, err := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_installation_administrator_bootstrap_receipts", workspaceID).
		Columns("id", "invocation_id", "request_fingerprint", "contract_version", "contract_hash", "user_id", "login_id", "created_at").
		Values(receipt.ID, receipt.InvocationID, receipt.RequestFingerprint, receipt.ContractVersion, receipt.ContractHash, receipt.UserID, receipt.LoginID, receipt.CreatedAt).Build()
	if err != nil {
		return err
	}
	if _, err := execer.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("insert installation administrator receipt: %w", err)
	}
	return nil
}

func (s *SQLIdentityStore) GetCommittedInstallationAdministratorBootstrapReceipt(ctx context.Context, workspaceID, receiptID string) (InstallationAdministratorBootstrapReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_installation_administrator_bootstrap_receipts", workspaceID).
		Columns("id", "invocation_id", "request_fingerprint", "contract_version", "contract_hash", "user_id", "login_id", "credential_claimed_at", "credential_delivered_at", "created_at").
		Where(query.Equal("id", strings.TrimSpace(receiptID))).Limit(1).Build()
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	receipt, err := scanInstallationAdministratorBootstrapReceipt(s.DB().QueryRowContext(ctx, statement, arguments...))
	if errors.Is(err, sql.ErrNoRows) {
		return InstallationAdministratorBootstrapReceipt{}, false, nil
	}
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	receipt.WorkspaceID = workspaceID
	return receipt, true, nil
}

func (s *SQLIdentityStore) MarkInstallationAdministratorCredentialClaimed(ctx context.Context, workspaceID, receiptID string) (bool, error) {
	return s.markInstallationAdministratorCredential(ctx, workspaceID, receiptID, "credential_claimed_at", query.IsNull("credential_claimed_at"))
}

func (s *SQLIdentityStore) MarkInstallationAdministratorCredentialDelivered(ctx context.Context, workspaceID, receiptID string) (bool, error) {
	return s.markInstallationAdministratorCredential(ctx, workspaceID, receiptID, "credential_delivered_at", query.And(query.IsNotNull("credential_claimed_at"), query.IsNull("credential_delivered_at")))
}

func (s *SQLIdentityStore) markInstallationAdministratorCredential(ctx context.Context, workspaceID, receiptID, column string, predicate query.Predicate) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_installation_administrator_bootstrap_receipts", workspaceID).
		Set(column, nowString()).Where(query.And(query.Equal("id", strings.TrimSpace(receiptID)), predicate)).Build()
	if err != nil {
		return false, err
	}
	result, err := s.DB().ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func scanInstallationAdministratorBootstrapReceipt(row *sql.Row) (InstallationAdministratorBootstrapReceipt, error) {
	var receipt InstallationAdministratorBootstrapReceipt
	var claimed, delivered sql.NullString
	err := row.Scan(&receipt.ID, &receipt.InvocationID, &receipt.RequestFingerprint, &receipt.ContractVersion, &receipt.ContractHash, &receipt.UserID, &receipt.LoginID, &claimed, &delivered, &receipt.CreatedAt)
	if claimed.Valid {
		receipt.CredentialClaimedAt = claimed.String
	}
	if delivered.Valid {
		receipt.CredentialDeliveredAt = delivered.String
	}
	return receipt, err
}
