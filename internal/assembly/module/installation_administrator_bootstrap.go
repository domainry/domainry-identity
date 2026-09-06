package moduleassembly

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"golang.org/x/crypto/bcrypt"
)

func (binding *moduleBinding) InstallationAdministratorBootstrap() identitymodulehost.InstallationAdministratorBootstrapV1 {
	if binding == nil || binding.runtime == nil {
		return nil
	}
	return binding
}

func (binding *moduleBinding) BootstrapInstallationAdministratorV1(ctx context.Context, request identitymodulehost.InstallationAdministratorBootstrapRequest, transaction identitymodulehost.Transaction) (identitymodulehost.InstallationAdministratorBootstrapReceipt, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.IdentityStore == nil || !binding.runtime.AuthStore.Ready() || binding.runtime.Audit == nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, installationAdministratorError("identity.installation_administrator_bootstrap_unavailable", nil)
	}
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, installationAdministratorError("identity.installation_administrator_transaction_required", nil)
	}
	request = normalizeInstallationAdministratorRequest(request)
	if err := validateInstallationAdministratorRequest(request); err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, err
	}
	fingerprint := installationAdministratorFingerprint(request)
	stored, found, err := binding.runtime.IdentityStore.GetInstallationAdministratorBootstrapReceiptWithExecutor(ctx, tx, request.WorkspaceID, request.InvocationID)
	if err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, fmt.Errorf("load installation administrator receipt: %w", err)
	}
	if found {
		if stored.RequestFingerprint != fingerprint || stored.ContractVersion != request.ContractVersion || stored.ContractHash != request.ContractHash {
			return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, installationAdministratorError("identity.installation_administrator_idempotency_conflict", nil)
		}
		return installationAdministratorReceipt(stored, true), nil
	}
	companyID, occupied, err := binding.runtime.IdentityStore.InstallationAdministratorBootstrapStateWithExecutor(ctx, tx, request.WorkspaceID, request.LoginID)
	if err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, fmt.Errorf("inspect installation administrator state: %w", err)
	}
	if occupied {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, installationAdministratorError("identity.installation_administrator_already_exists", nil)
	}
	userID, err := installationAdministratorUserID()
	if err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, err
	}
	password, err := workspaceInitialPassword()
	if err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, fmt.Errorf("hash installation administrator credential: %w", err)
	}
	receipt := identitypersistence.InstallationAdministratorBootstrapReceipt{
		ID:          identitypersistence.InstallationAdministratorBootstrapReceiptID(request.WorkspaceID, request.InvocationID),
		WorkspaceID: request.WorkspaceID, InvocationID: request.InvocationID, RequestFingerprint: fingerprint,
		ContractVersion: request.ContractVersion, ContractHash: request.ContractHash, UserID: userID, LoginID: request.LoginID,
	}
	if err := binding.runtime.IdentityStore.InsertInstallationAdministratorWithExecutor(ctx, tx, request.WorkspaceID, identitymodel.IdentityUser{
		ID: userID, Name: request.Name, Email: request.LoginID, AccountType: identitymodel.IdentityAccountHuman,
		OrgID: companyID, ReportingPath: "/" + userID, Status: identitymodel.IdentityStatusActive,
	}, receipt); err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, err
	}
	if err := binding.runtime.AuthStore.UpsertIdentityCredentialWithExecutor(ctx, tx, request.WorkspaceID, identitymodel.IdentityCredential{
		UserID: userID, PasswordHash: string(passwordHash), MustChangePassword: true,
	}); err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, fmt.Errorf("create installation administrator credential: %w", err)
	}
	principal := identitymodel.NewSystemPrincipal("installation_administrator_bootstrap", identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "first installation administrator issuance"), identitymodel.RoleSchema{})
	principal.WorkspaceID, principal.RequestID = request.WorkspaceID, request.InvocationID
	if err := binding.runtime.Audit.AppendAudit(identitytransaction.WithExecutor(ctx, tx), auditapplication.AuditAppendRequest{
		IdempotencyKey: request.InvocationID, Event: "identity.installation_administrator.bootstrap",
		ObjectKey: "identity.installation_administrator", RecordID: userID, Principal: principal,
		Summary:  "Issued first installation administrator",
		Metadata: map[string]any{"contract_version": request.ContractVersion, "contract_hash": request.ContractHash, "role_key": identitysdk.WorkspaceBootstrapRoleTenantAdmin},
	}); err != nil {
		return identitymodulehost.InstallationAdministratorBootstrapReceipt{}, fmt.Errorf("audit installation administrator issuance: %w", err)
	}
	binding.storeWorkspaceBootstrapCredential(receipt.ID, request.WorkspaceID, request.LoginID, []byte(password))
	return installationAdministratorReceipt(receipt, false), nil
}

func (binding *moduleBinding) CompleteInstallationAdministratorBootstrapV1(ctx context.Context, completion identitymodulehost.InstallationAdministratorBootstrapCompletion) error {
	if binding == nil || binding.runtime == nil || binding.runtime.IdentityStore == nil {
		return installationAdministratorError("identity.installation_administrator_bootstrap_unavailable", nil)
	}
	completion.WorkspaceID, completion.ReceiptID = strings.TrimSpace(completion.WorkspaceID), strings.TrimSpace(completion.ReceiptID)
	if _, err := identitymodel.NewWorkspaceID(completion.WorkspaceID); err != nil || completion.ReceiptID == "" {
		return installationAdministratorError("identity.installation_administrator_completion_invalid", err)
	}
	switch completion.Outcome {
	case identitysdk.WorkspaceIdentityBootstrapTransactionRolledBack:
		binding.discardWorkspaceBootstrapCredential(completion.ReceiptID)
		return nil
	case identitysdk.WorkspaceIdentityBootstrapTransactionCommitted:
		receipt, found, err := binding.runtime.IdentityStore.GetCommittedInstallationAdministratorBootstrapReceipt(ctx, completion.WorkspaceID, completion.ReceiptID)
		if err != nil {
			binding.discardWorkspaceBootstrapCredential(completion.ReceiptID)
			return err
		}
		if !found {
			binding.discardWorkspaceBootstrapCredential(completion.ReceiptID)
			return installationAdministratorError("identity.installation_administrator_credential_not_committed", nil)
		}
		binding.bootstrapMu.Lock()
		credential, available := binding.bootstrapCredentials[completion.ReceiptID]
		if available && credential.workspaceID == completion.WorkspaceID && credential.loginID == receipt.LoginID {
			credential.committed = true
		}
		binding.bootstrapMu.Unlock()
		if !available || credential.workspaceID != completion.WorkspaceID || credential.loginID != receipt.LoginID {
			return installationAdministratorError("identity.installation_administrator_credential_unavailable", nil)
		}
		return nil
	default:
		return installationAdministratorError("identity.installation_administrator_completion_invalid", nil)
	}
}

func (binding *moduleBinding) ClaimInstallationAdministratorCredentialV1(ctx context.Context, claim identitymodulehost.InstallationAdministratorCredentialClaim) (identitymodulehost.InstallationAdministratorOneTimeCredential, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.IdentityStore == nil {
		return identitymodulehost.InstallationAdministratorOneTimeCredential{}, installationAdministratorError("identity.installation_administrator_bootstrap_unavailable", nil)
	}
	claim.WorkspaceID, claim.ReceiptID = strings.TrimSpace(claim.WorkspaceID), strings.TrimSpace(claim.ReceiptID)
	binding.bootstrapMu.Lock()
	defer binding.bootstrapMu.Unlock()
	credential, available := binding.bootstrapCredentials[claim.ReceiptID]
	if !available || credential.workspaceID != claim.WorkspaceID || !credential.committed {
		return identitymodulehost.InstallationAdministratorOneTimeCredential{}, installationAdministratorError("identity.installation_administrator_credential_unavailable", nil)
	}
	receipt, found, err := binding.runtime.IdentityStore.GetCommittedInstallationAdministratorBootstrapReceipt(ctx, claim.WorkspaceID, claim.ReceiptID)
	if err != nil || !found {
		return identitymodulehost.InstallationAdministratorOneTimeCredential{}, installationAdministratorError("identity.installation_administrator_credential_not_committed", err)
	}
	if receipt.CredentialClaimedAt != "" {
		return identitymodulehost.InstallationAdministratorOneTimeCredential{}, installationAdministratorError("identity.installation_administrator_credential_already_claimed", nil)
	}
	claimed, err := binding.runtime.IdentityStore.MarkInstallationAdministratorCredentialClaimed(ctx, claim.WorkspaceID, claim.ReceiptID)
	if err != nil || !claimed {
		return identitymodulehost.InstallationAdministratorOneTimeCredential{}, installationAdministratorError("identity.installation_administrator_credential_already_claimed", err)
	}
	delete(binding.bootstrapCredentials, claim.ReceiptID)
	credential.timer.Stop()
	password := string(credential.password)
	clear(credential.password)
	return identitymodulehost.InstallationAdministratorOneTimeCredential{LoginID: credential.loginID, InitialPassword: password, MustChangePassword: true}, nil
}

func (binding *moduleBinding) AcknowledgeInstallationAdministratorCredentialDeliveryV1(ctx context.Context, acknowledgment identitymodulehost.InstallationAdministratorCredentialDeliveryAcknowledgment) error {
	if binding == nil || binding.runtime == nil || binding.runtime.IdentityStore == nil {
		return installationAdministratorError("identity.installation_administrator_bootstrap_unavailable", nil)
	}
	marked, err := binding.runtime.IdentityStore.MarkInstallationAdministratorCredentialDelivered(ctx, strings.TrimSpace(acknowledgment.WorkspaceID), strings.TrimSpace(acknowledgment.ReceiptID))
	if err != nil {
		return err
	}
	if !marked {
		receipt, found, lookupErr := binding.runtime.IdentityStore.GetCommittedInstallationAdministratorBootstrapReceipt(ctx, acknowledgment.WorkspaceID, acknowledgment.ReceiptID)
		if lookupErr != nil || !found || receipt.CredentialDeliveredAt == "" {
			return installationAdministratorError("identity.installation_administrator_delivery_acknowledgment_invalid", lookupErr)
		}
	}
	return nil
}

func normalizeInstallationAdministratorRequest(request identitymodulehost.InstallationAdministratorBootstrapRequest) identitymodulehost.InstallationAdministratorBootstrapRequest {
	request.ContractVersion, request.ContractHash = strings.TrimSpace(request.ContractVersion), strings.TrimSpace(request.ContractHash)
	request.InvocationID, request.WorkspaceID = strings.TrimSpace(request.InvocationID), strings.TrimSpace(request.WorkspaceID)
	request.LoginID, request.Name = strings.ToLower(strings.TrimSpace(request.LoginID)), strings.TrimSpace(request.Name)
	return request
}

func validateInstallationAdministratorRequest(request identitymodulehost.InstallationAdministratorBootstrapRequest) error {
	if request.ContractVersion != identitymodulehost.CurrentInstallationAdministratorBootstrapContractVersion || request.ContractHash != identitymodulehost.CurrentInstallationAdministratorBootstrapContractHash {
		return installationAdministratorError("identity.installation_administrator_contract_unsupported", nil)
	}
	if _, err := identitymodel.NewWorkspaceID(request.WorkspaceID); err != nil {
		return installationAdministratorError("identity.installation_administrator_request_invalid", err)
	}
	if err := identitysdk.ValidateIdentifier("invocation_id", request.InvocationID); err != nil || strings.Contains(request.InvocationID, "/") || request.LoginID == "" || request.Name == "" {
		return installationAdministratorError("identity.installation_administrator_request_invalid", err)
	}
	return nil
}

func installationAdministratorFingerprint(request identitymodulehost.InstallationAdministratorBootstrapRequest) string {
	canonical, _ := json.Marshal([]string{request.ContractVersion, request.ContractHash, request.InvocationID, request.WorkspaceID, request.LoginID, request.Name})
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func installationAdministratorUserID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate installation administrator identity: %w", err)
	}
	return "installation-admin-" + hex.EncodeToString(buffer), nil
}

func installationAdministratorReceipt(stored identitypersistence.InstallationAdministratorBootstrapReceipt, replayed bool) identitymodulehost.InstallationAdministratorBootstrapReceipt {
	return identitymodulehost.InstallationAdministratorBootstrapReceipt{
		ContractVersion: stored.ContractVersion, ContractHash: stored.ContractHash, ReceiptID: stored.ID,
		InvocationID: stored.InvocationID, WorkspaceID: stored.WorkspaceID, UserID: stored.UserID,
		LoginID: stored.LoginID, RoleKey: identitysdk.WorkspaceBootstrapRoleTenantAdmin, Replayed: replayed,
		CredentialClaimed: stored.CredentialClaimedAt != "", CredentialDelivered: stored.CredentialDeliveredAt != "",
	}
}

func installationAdministratorError(code string, cause error) *identitysdk.Error {
	return &identitysdk.Error{Code: code, Cause: cause}
}

var _ identitysdk.EmbeddedInstallationAdministratorBootstrapBinding = (*moduleBinding)(nil)
var _ identitymodulehost.InstallationAdministratorBootstrapV1 = (*moduleBinding)(nil)
