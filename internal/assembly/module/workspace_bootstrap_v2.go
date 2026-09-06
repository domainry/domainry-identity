package moduleassembly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"golang.org/x/crypto/bcrypt"
)

const workspaceBootstrapCredentialTTL = 5 * time.Minute

type workspaceBootstrapPendingCredential struct {
	workspaceID string
	loginID     string
	password    []byte
	committed   bool
	timer       *time.Timer
}

// BootstrapWorkspaceIdentityV2 implements the Protocol V3 bootstrap boundary.
// The caller supplies graph identity but cannot choose roles or credentials.
// Every durable write joins the host-owned transaction and the transaction-
// phase response contains only a non-secret receipt.
func (binding *moduleBinding) BootstrapWorkspaceIdentityV2(ctx context.Context, request identitysdk.WorkspaceIdentityBootstrapV2Request, transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceIdentityBootstrapV2Receipt, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil || binding.runtime.IdentityActions == nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, bootstrapV2Error("identity.workspace_bootstrap_transaction_required", nil)
	}
	request = normalizeWorkspaceBootstrapV2Request(request)
	if err := validateWorkspaceBootstrapV2Request(request); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
	}
	fingerprint := workspaceBootstrapV2Fingerprint(request)
	stored, found, err := binding.runtime.IdentityStore.GetWorkspaceIdentityBootstrapReceiptWithExecutor(ctx, tx, request.WorkspaceID, request.InvocationID)
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("load workspace bootstrap receipt: %w", err)
	}
	if found {
		if stored.RequestFingerprint != fingerprint || stored.ContractVersion != request.ContractVersion || stored.ContractHash != request.ContractHash {
			return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, bootstrapV2Error("identity.workspace_bootstrap_idempotency_conflict", nil)
		}
		return workspaceBootstrapV2Receipt(stored, true), nil
	}
	if exists, err := binding.runtime.IdentityStore.WorkspaceIdentityBootstrapReceiptExistsWithExecutor(ctx, tx, request.WorkspaceID); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("inspect workspace bootstrap receipt: %w", err)
	} else if exists {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, bootstrapV2Error("identity.workspace_bootstrap_already_completed", nil)
	}
	if exists, err := binding.runtime.IdentityStore.WorkspaceIdentityBootstrapStateExistsWithExecutor(ctx, tx, request.WorkspaceID); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("inspect workspace bootstrap state: %w", err)
	} else if exists {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, bootstrapV2Error("identity.workspace_bootstrap_state_conflict", nil)
	}

	password, err := workspaceInitialPassword()
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("hash workspace bootstrap credential: %w", err)
	}
	roles, err := binding.workspaceBootstrapV2Roles(request.WorkspaceID)
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
	}
	adminRoleID := identitypersistence.WorkspaceRoleID(request.WorkspaceID, identitysdk.WorkspaceBootstrapRoleHeadquartersAdmin)
	companyID := request.CompanyID
	graph := identitypersistence.WorkspaceIdentityBootstrapGraph{
		Company: identitymodel.IdentityOrganizationUnit{
			ID: companyID, Code: request.CompanyCode, Name: request.CompanyName,
			NodeType: identitymodel.IdentityOrganizationUnitCompany, Path: "/" + companyID,
			AncestorIDs: []string{}, Depth: 0, SortOrder: 0, Status: identitymodel.IdentityStatusActive,
		},
		FirstStore: identitymodel.IdentityOrganizationUnit{
			ID: request.FirstStoreID, Code: request.FirstStoreCode, Name: request.FirstStoreName,
			NodeType: identitymodel.IdentityOrganizationUnitStore, ParentID: &companyID,
			Path: "/" + companyID + "/" + request.FirstStoreID, AncestorIDs: []string{companyID},
			Depth: 1, SortOrder: 0, Status: identitymodel.IdentityStatusActive,
		},
		InitialAdmin: identitymodel.IdentityUser{
			ID: request.InitialAdminUserID, Name: request.InitialAdminName, Email: request.InitialAdminLoginID,
			AccountType: identitymodel.IdentityAccountHuman, OrgID: companyID,
			ReportingPath: "/" + request.InitialAdminUserID, Status: identitymodel.IdentityStatusActive,
		},
		Roles: roles, AdminRoleID: adminRoleID,
	}
	if err := binding.runtime.IdentityStore.WriteWorkspaceIdentityBootstrapGraphWithExecutor(ctx, tx, request.WorkspaceID, graph, func(stage identitypersistence.WorkspaceIdentityProvisionStage) error {
		return injectWorkspaceBootstrapV2Failure(transaction.WorkspaceProvisionFailures, stage)
	}); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
	}
	permissionCatalog, err := identityapplication.NewIdentityPermissionCatalogApplicationService(binding.runtime.IdentityStore, binding.runtime.IdentityActions, request.WorkspaceID)
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("assemble workspace bootstrap permission catalog: %w", err)
	}
	if _, err := permissionCatalog.ReconcileOwner(identitytransaction.WithExecutor(ctx, tx), identityapplication.IdentityBuiltinAuthorizationOwner); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("provision workspace bootstrap permissions: %w", err)
	}
	if err := binding.runtime.AuthStore.UpsertIdentityCredentialWithExecutor(ctx, tx, request.WorkspaceID, identitymodel.IdentityCredential{
		UserID: request.InitialAdminUserID, PasswordHash: string(passwordHash), MustChangePassword: true,
	}); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, fmt.Errorf("provision workspace bootstrap credential: %w", err)
	}
	if transaction.WorkspaceProvisionFailures != nil {
		if err := transaction.WorkspaceProvisionFailures.InjectWorkspaceProvisionFailure(identitysdk.WorkspaceProvisionFailureAfterCredential); err != nil {
			return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
		}
	}
	receipt := identitypersistence.WorkspaceIdentityBootstrapReceipt{
		ID:          identitypersistence.WorkspaceIdentityBootstrapReceiptID(request.WorkspaceID, request.InvocationID),
		WorkspaceID: request.WorkspaceID, InvocationID: request.InvocationID, RequestFingerprint: fingerprint,
		ContractVersion: request.ContractVersion, ContractHash: request.ContractHash,
		CompanyID: request.CompanyID, FirstStoreID: request.FirstStoreID,
		InitialAdminUserID: request.InitialAdminUserID, InitialAdminLoginID: request.InitialAdminLoginID,
	}
	if err := binding.runtime.IdentityStore.InsertWorkspaceIdentityBootstrapReceiptWithExecutor(ctx, tx, receipt); err != nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
	}
	if transaction.WorkspaceProvisionFailures != nil {
		if err := transaction.WorkspaceProvisionFailures.InjectWorkspaceProvisionFailure(identitysdk.WorkspaceProvisionFailureAfterBootstrapReceipt); err != nil {
			return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, err
		}
	}
	binding.storeWorkspaceBootstrapCredential(receipt.ID, request.WorkspaceID, request.InitialAdminLoginID, []byte(password))
	return workspaceBootstrapV2Receipt(receipt, false), nil
}

// CompleteWorkspaceIdentityBootstrapV2 is the host's mandatory completion
// hook. Rollback destroys the volatile secret immediately. Commit must be
// visible through the ordinary database pool before the secret becomes
// claimable; all pending secrets also expire after a short bounded lifetime.
func (binding *moduleBinding) CompleteWorkspaceIdentityBootstrapV2(ctx context.Context, completion identitysdk.WorkspaceIdentityBootstrapCompletion) error {
	if binding == nil || binding.runtime == nil || binding.runtime.IdentityStore == nil {
		return bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	completion.WorkspaceID = strings.TrimSpace(completion.WorkspaceID)
	completion.ReceiptID = strings.TrimSpace(completion.ReceiptID)
	if _, err := identitymodel.NewWorkspaceID(completion.WorkspaceID); err != nil || completion.ReceiptID == "" {
		return bootstrapV2Error("identity.workspace_bootstrap_completion_invalid", err)
	}
	switch completion.Outcome {
	case identitysdk.WorkspaceIdentityBootstrapTransactionRolledBack:
		binding.discardWorkspaceBootstrapCredential(completion.ReceiptID)
		return nil
	case identitysdk.WorkspaceIdentityBootstrapTransactionCommitted:
		receipt, found, err := binding.runtime.IdentityStore.GetCommittedWorkspaceIdentityBootstrapReceipt(ctx, completion.WorkspaceID, completion.ReceiptID)
		if err != nil {
			binding.discardWorkspaceBootstrapCredential(completion.ReceiptID)
			return fmt.Errorf("verify committed workspace bootstrap receipt: %w", err)
		}
		if !found {
			binding.discardWorkspaceBootstrapCredential(completion.ReceiptID)
			return bootstrapV2Error("identity.workspace_bootstrap_credential_not_committed", nil)
		}
		binding.bootstrapMu.Lock()
		credential, available := binding.bootstrapCredentials[completion.ReceiptID]
		if available && credential.workspaceID == completion.WorkspaceID && receipt.InitialAdminLoginID == credential.loginID {
			credential.committed = true
		}
		binding.bootstrapMu.Unlock()
		if !available || credential.workspaceID != completion.WorkspaceID || receipt.InitialAdminLoginID != credential.loginID {
			return bootstrapV2Error("identity.workspace_bootstrap_credential_unavailable", nil)
		}
		return nil
	default:
		return bootstrapV2Error("identity.workspace_bootstrap_completion_invalid", nil)
	}
}

// ClaimWorkspaceIdentityBootstrapCredentialV2 reads through the ordinary
// database pool, and also requires the host's verified commit completion, so
// an uncommitted or rolled-back receipt can never release a credential.
func (binding *moduleBinding) ClaimWorkspaceIdentityBootstrapCredentialV2(ctx context.Context, claim identitysdk.WorkspaceIdentityBootstrapCredentialClaim) (identitysdk.WorkspaceIdentityBootstrapOneTimeCredential, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.IdentityStore == nil {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	claim.WorkspaceID = strings.TrimSpace(claim.WorkspaceID)
	claim.ReceiptID = strings.TrimSpace(claim.ReceiptID)
	if _, err := identitymodel.NewWorkspaceID(claim.WorkspaceID); err != nil || claim.ReceiptID == "" {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_credential_claim_invalid", err)
	}
	binding.bootstrapMu.Lock()
	defer binding.bootstrapMu.Unlock()
	credential, available := binding.bootstrapCredentials[claim.ReceiptID]
	if !available || credential.workspaceID != claim.WorkspaceID {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_credential_unavailable", nil)
	}
	if !credential.committed {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_completion_required", nil)
	}
	receipt, found, err := binding.runtime.IdentityStore.GetCommittedWorkspaceIdentityBootstrapReceipt(ctx, claim.WorkspaceID, claim.ReceiptID)
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, fmt.Errorf("load committed workspace bootstrap receipt: %w", err)
	}
	if !found {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_credential_not_committed", nil)
	}
	if receipt.CredentialClaimedAt != "" {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_credential_already_claimed", nil)
	}
	claimed, err := binding.runtime.IdentityStore.MarkWorkspaceIdentityBootstrapCredentialClaimed(ctx, claim.WorkspaceID, claim.ReceiptID)
	if err != nil {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, fmt.Errorf("claim workspace bootstrap credential: %w", err)
	}
	if !claimed {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_credential_already_claimed", nil)
	}
	delete(binding.bootstrapCredentials, claim.ReceiptID)
	credential.timer.Stop()
	password := string(credential.password)
	clear(credential.password)
	return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{LoginID: credential.loginID, InitialPassword: password, MustChangePassword: true}, nil
}

func (binding *moduleBinding) storeWorkspaceBootstrapCredential(receiptID, workspaceID, loginID string, password []byte) {
	credential := &workspaceBootstrapPendingCredential{workspaceID: workspaceID, loginID: loginID, password: append([]byte(nil), password...)}
	binding.bootstrapMu.Lock()
	if binding.bootstrapCredentials == nil {
		binding.bootstrapCredentials = make(map[string]*workspaceBootstrapPendingCredential)
	}
	if previous := binding.bootstrapCredentials[receiptID]; previous != nil {
		previous.timer.Stop()
		clear(previous.password)
	}
	binding.bootstrapCredentials[receiptID] = credential
	credential.timer = time.AfterFunc(workspaceBootstrapCredentialTTL, func() {
		binding.expireWorkspaceBootstrapCredential(receiptID, credential)
	})
	binding.bootstrapMu.Unlock()
}

func (binding *moduleBinding) expireWorkspaceBootstrapCredential(receiptID string, expected *workspaceBootstrapPendingCredential) {
	binding.bootstrapMu.Lock()
	credential, found := binding.bootstrapCredentials[receiptID]
	if !found || credential != expected {
		binding.bootstrapMu.Unlock()
		return
	}
	delete(binding.bootstrapCredentials, receiptID)
	binding.bootstrapMu.Unlock()
	clear(credential.password)
}

func (binding *moduleBinding) discardWorkspaceBootstrapCredential(receiptID string) {
	binding.bootstrapMu.Lock()
	credential, found := binding.bootstrapCredentials[receiptID]
	delete(binding.bootstrapCredentials, receiptID)
	binding.bootstrapMu.Unlock()
	if found {
		credential.timer.Stop()
		clear(credential.password)
	}
}

func normalizeWorkspaceBootstrapV2Request(request identitysdk.WorkspaceIdentityBootstrapV2Request) identitysdk.WorkspaceIdentityBootstrapV2Request {
	request.ContractVersion = strings.TrimSpace(request.ContractVersion)
	request.ContractHash = strings.TrimSpace(request.ContractHash)
	request.InvocationID = strings.TrimSpace(request.InvocationID)
	request.WorkspaceID = strings.TrimSpace(request.WorkspaceID)
	request.CompanyID = strings.TrimSpace(request.CompanyID)
	request.CompanyCode = strings.TrimSpace(request.CompanyCode)
	request.CompanyName = strings.TrimSpace(request.CompanyName)
	request.FirstStoreID = strings.TrimSpace(request.FirstStoreID)
	request.FirstStoreCode = strings.TrimSpace(request.FirstStoreCode)
	request.FirstStoreName = strings.TrimSpace(request.FirstStoreName)
	request.InitialAdminUserID = strings.TrimSpace(request.InitialAdminUserID)
	request.InitialAdminLoginID = strings.ToLower(strings.TrimSpace(request.InitialAdminLoginID))
	request.InitialAdminName = strings.TrimSpace(request.InitialAdminName)
	return request
}

func validateWorkspaceBootstrapV2Request(request identitysdk.WorkspaceIdentityBootstrapV2Request) error {
	if request.ContractVersion != identitysdk.CurrentWorkspaceIdentityBootstrapContractVersion || request.ContractHash != identitysdk.CurrentWorkspaceIdentityBootstrapContractHash {
		return bootstrapV2Error("identity.workspace_bootstrap_contract_unsupported", nil)
	}
	if _, err := identitymodel.NewWorkspaceID(request.WorkspaceID); err != nil {
		return bootstrapV2Error("identity.workspace_bootstrap_invalid", err)
	}
	identifiers := map[string]string{
		"invocation_id": request.InvocationID, "company_id": request.CompanyID,
		"first_store_id": request.FirstStoreID, "initial_admin_user_id": request.InitialAdminUserID,
	}
	for field, value := range identifiers {
		if err := identitysdk.ValidateIdentifier(field, value); err != nil || strings.Contains(value, "/") {
			return &identitysdk.Error{Code: "identity.workspace_bootstrap_invalid", Cause: err, Params: map[string]string{"field": field}}
		}
	}
	values := []string{request.CompanyCode, request.CompanyName, request.FirstStoreCode, request.FirstStoreName, request.InitialAdminLoginID, request.InitialAdminName}
	for _, value := range values {
		if value == "" {
			return bootstrapV2Error("identity.workspace_bootstrap_invalid", nil)
		}
	}
	if request.CompanyID == request.FirstStoreID || strings.EqualFold(request.CompanyCode, request.FirstStoreCode) {
		return bootstrapV2Error("identity.workspace_bootstrap_invalid", nil)
	}
	return nil
}

func workspaceBootstrapV2Fingerprint(request identitysdk.WorkspaceIdentityBootstrapV2Request) string {
	values := []string{
		request.ContractVersion, request.ContractHash, request.InvocationID, request.WorkspaceID,
		request.CompanyID, request.CompanyCode, request.CompanyName,
		request.FirstStoreID, request.FirstStoreCode, request.FirstStoreName,
		request.InitialAdminUserID, request.InitialAdminLoginID, request.InitialAdminName,
	}
	canonical, _ := json.Marshal(values)
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func workspaceBootstrapV2Receipt(receipt identitypersistence.WorkspaceIdentityBootstrapReceipt, replayed bool) identitysdk.WorkspaceIdentityBootstrapV2Receipt {
	return identitysdk.WorkspaceIdentityBootstrapV2Receipt{
		ContractVersion: receipt.ContractVersion, ContractHash: receipt.ContractHash,
		ReceiptID: receipt.ID, InvocationID: receipt.InvocationID, WorkspaceID: receipt.WorkspaceID,
		CompanyID: receipt.CompanyID, FirstStoreID: receipt.FirstStoreID,
		InitialAdminUserID: receipt.InitialAdminUserID, InitialAdminLoginID: receipt.InitialAdminLoginID,
		Replayed: replayed,
	}
}

func (binding *moduleBinding) workspaceBootstrapV2Roles(workspaceID string) ([]identitymodel.IdentityRole, error) {
	binding.bootstrapMu.Lock()
	labels := make(map[string]string, len(binding.bootstrapRoleLabels))
	for key, label := range binding.bootstrapRoleLabels {
		labels[key] = label
	}
	binding.bootstrapMu.Unlock()
	keys := []string{
		identitysdk.WorkspaceBootstrapRoleTenantAdmin,
		identitysdk.WorkspaceBootstrapRoleHeadquartersAdmin,
		identitysdk.WorkspaceBootstrapRoleStoreManager,
		identitysdk.WorkspaceBootstrapRoleStaff,
	}
	roles := make([]identitymodel.IdentityRole, 0, len(keys))
	for _, key := range keys {
		label, found := labels[key]
		if !found {
			return nil, &identitysdk.Error{Code: "identity.workspace_bootstrap_role_catalog_incomplete", Params: map[string]string{"role_key": key}}
		}
		if label == "" {
			label = key
		}
		if key == identitysdk.WorkspaceBootstrapRoleTenantAdmin {
			label = "Platform administrator"
		}
		roles = append(roles, identitymodel.IdentityRole{
			ID: identitypersistence.WorkspaceRoleID(workspaceID, key), Key: key, Label: label,
			Description: "Protocol V2 fixed workspace bootstrap role", Status: identitymodel.IdentityStatusActive,
		})
	}
	return roles, nil
}

func injectWorkspaceBootstrapV2Failure(injector identitysdk.WorkspaceProvisionFailureInjector, stage identitypersistence.WorkspaceIdentityProvisionStage) error {
	if injector == nil {
		return nil
	}
	points := map[identitypersistence.WorkspaceIdentityProvisionStage]string{
		identitypersistence.WorkspaceIdentityProvisionStageCompany:        identitysdk.WorkspaceProvisionFailureAfterCompany,
		identitypersistence.WorkspaceIdentityProvisionStageFirstStore:     identitysdk.WorkspaceProvisionFailureAfterFirstStore,
		identitypersistence.WorkspaceIdentityProvisionStageUser:           identitysdk.WorkspaceProvisionFailureAfterIdentityUser,
		identitypersistence.WorkspaceIdentityProvisionStageRole:           identitysdk.WorkspaceProvisionFailureAfterIdentityRole,
		identitypersistence.WorkspaceIdentityProvisionStageRoleAssignment: identitysdk.WorkspaceProvisionFailureAfterRoleAssignment,
	}
	if point := points[stage]; point != "" {
		return injector.InjectWorkspaceProvisionFailure(point)
	}
	return nil
}

func bootstrapV2Error(code string, cause error) *identitysdk.Error {
	return &identitysdk.Error{Code: code, Cause: cause}
}

var _ identitysdk.EmbeddedWorkspaceIdentityBootstrapV2 = (*moduleBinding)(nil)

// bootstrapBinding prevents the legacy V1 WorkspaceProvisioner methods on the
// implementation from leaking through a dynamic type assertion on the V3
// bootstrap factory result. Ordinary workspace-bound bindings retain V1 for
// compatibility with existing hosts.
type bootstrapBinding struct{ inner *moduleBinding }

func newBootstrapBinding(inner *moduleBinding) identitysdk.BootstrapBinding {
	return &bootstrapBinding{inner: inner}
}

func (binding *bootstrapBinding) BootstrapWorkspaceIdentityV2(ctx context.Context, request identitysdk.WorkspaceIdentityBootstrapV2Request, transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceIdentityBootstrapV2Receipt, error) {
	if binding == nil {
		return identitysdk.WorkspaceIdentityBootstrapV2Receipt{}, bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	return binding.inner.BootstrapWorkspaceIdentityV2(ctx, request, transaction)
}

func (binding *bootstrapBinding) ClaimWorkspaceIdentityBootstrapCredentialV2(ctx context.Context, claim identitysdk.WorkspaceIdentityBootstrapCredentialClaim) (identitysdk.WorkspaceIdentityBootstrapOneTimeCredential, error) {
	if binding == nil {
		return identitysdk.WorkspaceIdentityBootstrapOneTimeCredential{}, bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	return binding.inner.ClaimWorkspaceIdentityBootstrapCredentialV2(ctx, claim)
}

func (binding *bootstrapBinding) CompleteWorkspaceIdentityBootstrapV2(ctx context.Context, completion identitysdk.WorkspaceIdentityBootstrapCompletion) error {
	if binding == nil {
		return bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	return binding.inner.CompleteWorkspaceIdentityBootstrapV2(ctx, completion)
}

func (binding *bootstrapBinding) BindBootstrapProjectRoleCatalog(ctx context.Context, catalog identitysdk.ProjectRoleCatalog) error {
	if binding == nil {
		return bootstrapV2Error("identity.workspace_bootstrap_unavailable", nil)
	}
	return binding.inner.BindBootstrapProjectRoleCatalog(ctx, catalog)
}

func (binding *bootstrapBinding) Close(ctx context.Context) error {
	if binding == nil {
		return nil
	}
	return binding.inner.Close(ctx)
}

func (binding *bootstrapBinding) WorkspaceAcceptanceFixtureProvisioner() identitysdk.EmbeddedWorkspaceAcceptanceFixtureProvisioner {
	if binding == nil {
		return nil
	}
	return binding.inner
}

var _ identitysdk.BootstrapBinding = (*bootstrapBinding)(nil)
var _ identitysdk.EmbeddedWorkspaceAcceptanceFixtureProvisionerBinding = (*bootstrapBinding)(nil)
