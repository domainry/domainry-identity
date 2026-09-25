package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	operationreceipt "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity/operationreceipt"
	"github.com/domainry/domainry-orm/query"
)

const (
	installationAdministratorRoleKey                 = "tenant_admin"
	installationAdministratorOperationOwner          = "identity"
	installationAdministratorOperationKind           = "identity.installation_administrator_bootstrap"
	installationAdministratorOperationIdempotencyKey = "installation_administrator_bootstrap"
)

type InstallationAdministratorBootstrapReceipt struct {
	ID                    string `json:"id"`
	WorkspaceID           string `json:"workspace_id"`
	InvocationID          string `json:"invocation_id"`
	RequestFingerprint    string `json:"request_fingerprint"`
	ContractVersion       string `json:"contract_version"`
	ContractHash          string `json:"contract_hash"`
	UserID                string `json:"user_id"`
	LoginID               string `json:"login_id"`
	CredentialClaimedAt   string `json:"credential_claimed_at,omitempty"`
	CredentialDeliveredAt string `json:"credential_delivered_at,omitempty"`
	CreatedAt             string `json:"created_at"`
}

type installationAdministratorBootstrapReceiptJSON struct {
	ID                    string `json:"id"`
	WorkspaceID           string `json:"workspace_id"`
	InvocationID          string `json:"invocation_id"`
	RequestFingerprint    string `json:"request_fingerprint"`
	ContractVersion       string `json:"contract_version"`
	ContractHash          string `json:"contract_hash"`
	UserID                string `json:"user_id"`
	LoginID               string `json:"login_id"`
	CredentialClaimedAt   int64  `json:"credential_claimed_at,omitempty"`
	CredentialDeliveredAt int64  `json:"credential_delivered_at,omitempty"`
	CreatedAt             int64  `json:"created_at"`
}

func (value InstallationAdministratorBootstrapReceipt) MarshalJSON() ([]byte, error) {
	return json.Marshal(installationAdministratorBootstrapReceiptJSON{
		ID: value.ID, WorkspaceID: value.WorkspaceID, InvocationID: value.InvocationID, RequestFingerprint: value.RequestFingerprint,
		ContractVersion: value.ContractVersion, ContractHash: value.ContractHash, UserID: value.UserID, LoginID: value.LoginID,
		CredentialClaimedAt: timeMillis(value.CredentialClaimedAt), CredentialDeliveredAt: timeMillis(value.CredentialDeliveredAt), CreatedAt: timeMillis(value.CreatedAt),
	})
}

func (value *InstallationAdministratorBootstrapReceipt) UnmarshalJSON(raw []byte) error {
	var stored installationAdministratorBootstrapReceiptJSON
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	*value = InstallationAdministratorBootstrapReceipt{
		ID: stored.ID, WorkspaceID: stored.WorkspaceID, InvocationID: stored.InvocationID, RequestFingerprint: stored.RequestFingerprint,
		ContractVersion: stored.ContractVersion, ContractHash: stored.ContractHash, UserID: stored.UserID, LoginID: stored.LoginID,
		CredentialClaimedAt: timeString(stored.CredentialClaimedAt), CredentialDeliveredAt: timeString(stored.CredentialDeliveredAt), CreatedAt: timeString(stored.CreatedAt),
	}
	return nil
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
	if !s.OperationsPersistenceBound() {
		return InstallationAdministratorBootstrapReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.LoadReferenced(ctx, execer, s.sqlRenderer(), workspaceID, installationAdministratorOperationOwner, installationAdministratorOperationKind, installationAdministratorOperationIdempotencyKey)
	if err != nil || !found {
		return InstallationAdministratorBootstrapReceipt{}, found, err
	}
	if operation.Reference != strings.TrimSpace(invocationID) {
		return InstallationAdministratorBootstrapReceipt{}, false, nil
	}
	return decodeInstallationAdministratorBootstrapReceipt(operation, workspaceID)
}

func (s *SQLIdentityStore) InstallationAdministratorBootstrapReceiptExistsWithExecutor(ctx context.Context, execer identityUserExecer, workspaceID string) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	if !s.OperationsPersistenceBound() {
		return false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	_, found, err := operationreceipt.Load(ctx, execer, s.sqlRenderer(), workspaceID, installationAdministratorOperationOwner, installationAdministratorOperationKind, installationAdministratorOperationIdempotencyKey)
	return found, err
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
	if !s.OperationsPersistenceBound() {
		return fmt.Errorf("identity shared Operations persistence is not bound")
	}
	if receipt.CreatedAt == "" {
		receipt.CreatedAt = nowString()
	}
	resultJSON, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	metadataJSON, _ := json.Marshal(map[string]string{"contract_version": receipt.ContractVersion, "contract_hash": receipt.ContractHash})
	relatedIDsJSON, _ := json.Marshal([]string{receipt.UserID})
	if err := operationreceipt.InsertSucceeded(ctx, execer, s.sqlRenderer(), operationreceipt.Succeeded{
		ID: receipt.ID, WorkspaceID: workspaceID, Owner: installationAdministratorOperationOwner, Kind: installationAdministratorOperationKind,
		ActionKey: "identity.installation_administrator.bootstrap", ResourceType: "identity_user", ResourceID: receipt.UserID,
		IdempotencyKey: installationAdministratorOperationIdempotencyKey, RequestFingerprint: receipt.RequestFingerprint,
		RequestedBy: "identity.installation_administrator_bootstrap", Reason: "bootstrap installation administrator", Reference: receipt.InvocationID,
		ResultJSON: resultJSON, MetadataJSON: metadataJSON, RelatedIDsJSON: relatedIDsJSON, CompletedAt: receipt.CreatedAt,
	}); err != nil {
		return fmt.Errorf("insert installation administrator receipt: %w", err)
	}
	return nil
}

func (s *SQLIdentityStore) GetCommittedInstallationAdministratorBootstrapReceipt(ctx context.Context, workspaceID, receiptID string) (InstallationAdministratorBootstrapReceipt, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, err
	}
	if !s.OperationsPersistenceBound() {
		return InstallationAdministratorBootstrapReceipt{}, false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.LoadByID(ctx, s.DB(), s.sqlRenderer(), workspaceID, installationAdministratorOperationOwner, installationAdministratorOperationKind, receiptID)
	if err != nil || !found {
		return InstallationAdministratorBootstrapReceipt{}, found, err
	}
	return decodeInstallationAdministratorBootstrapReceipt(operation, workspaceID)
}

func (s *SQLIdentityStore) MarkInstallationAdministratorCredentialClaimed(ctx context.Context, workspaceID, receiptID string) (bool, error) {
	return s.markInstallationAdministratorCredential(ctx, workspaceID, receiptID, false)
}

func (s *SQLIdentityStore) MarkInstallationAdministratorCredentialDelivered(ctx context.Context, workspaceID, receiptID string) (bool, error) {
	return s.markInstallationAdministratorCredential(ctx, workspaceID, receiptID, true)
}

func (s *SQLIdentityStore) markInstallationAdministratorCredential(ctx context.Context, workspaceID, receiptID string, delivered bool) (bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return false, err
	}
	if !s.OperationsPersistenceBound() {
		return false, fmt.Errorf("identity shared Operations persistence is not bound")
	}
	operation, found, err := operationreceipt.LoadByID(ctx, s.DB(), s.sqlRenderer(), workspaceID, installationAdministratorOperationOwner, installationAdministratorOperationKind, receiptID)
	if err != nil || !found {
		return false, err
	}
	receipt, found, err := decodeInstallationAdministratorBootstrapReceipt(operation, workspaceID)
	if err != nil || !found {
		return false, err
	}
	now := nowString()
	if delivered {
		if receipt.CredentialClaimedAt == "" || receipt.CredentialDeliveredAt != "" {
			return false, nil
		}
		receipt.CredentialDeliveredAt = now
	} else {
		if receipt.CredentialClaimedAt != "" {
			return false, nil
		}
		receipt.CredentialClaimedAt = now
	}
	next, err := json.Marshal(receipt)
	if err != nil {
		return false, err
	}
	return operationreceipt.UpdateSucceededResult(ctx, s.DB(), s.sqlRenderer(), workspaceID, installationAdministratorOperationOwner, installationAdministratorOperationKind, receiptID, operation.ResultJSON, next, now)
}

func decodeInstallationAdministratorBootstrapReceipt(operation operationreceipt.Receipt, workspaceID string) (InstallationAdministratorBootstrapReceipt, bool, error) {
	var receipt InstallationAdministratorBootstrapReceipt
	if err := json.Unmarshal(operation.ResultJSON, &receipt); err != nil {
		return InstallationAdministratorBootstrapReceipt{}, false, fmt.Errorf("decode installation administrator bootstrap operation: %w", err)
	}
	if receipt.ID != operation.ID || receipt.WorkspaceID != workspaceID || receipt.UserID != operation.ResourceID ||
		receipt.InvocationID != operation.Reference || receipt.RequestFingerprint != operation.RequestFingerprint || receipt.CreatedAt != operation.CreatedAt {
		return InstallationAdministratorBootstrapReceipt{}, false, fmt.Errorf("identity shared installation administrator operation scope mismatch")
	}
	return receipt, true, nil
}
