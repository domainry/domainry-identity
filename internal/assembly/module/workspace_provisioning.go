package moduleassembly

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"unicode"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"golang.org/x/crypto/bcrypt"
)

func (binding *moduleBinding) ProvisionWorkspaceIdentity(ctx context.Context, request identitysdk.WorkspaceIdentityProvisionRequest, transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceIdentityProvisionResult, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil || binding.runtime.IdentityActions == nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Code: "identity.workspace_provisioning_unavailable"}
	}
	tx, ok := transaction.Native.(*sql.Tx)
	if !ok || tx == nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Code: "identity.workspace_provisioning_transaction_required"}
	}
	request.WorkspaceID = strings.TrimSpace(request.WorkspaceID)
	request.AdminLoginID = strings.ToLower(strings.TrimSpace(request.AdminLoginID))
	request.AdminName = strings.TrimSpace(request.AdminName)
	if _, err := identitymodel.NewWorkspaceID(request.WorkspaceID); err != nil || request.AdminLoginID == "" || request.AdminName == "" {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Code: "identity.workspace_provisioning_invalid", Cause: err}
	}
	password := request.InitialPassword
	if password == "" {
		var err error
		password, err = workspaceInitialPassword()
		if err != nil {
			return identitysdk.WorkspaceIdentityProvisionResult{}, err
		}
	} else if !validBootstrapInitialPassword(password) {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Code: "identity.workspace_provisioning_initial_password_invalid"}
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("hash initial workspace password: %w", err)
	}
	roles := binding.provisionedWorkspaceRoles(request.WorkspaceID)
	admin := identitymodel.IdentityUser{
		ID: "admin", Name: request.AdminName, Email: request.AdminLoginID,
		AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive,
	}
	if err := binding.runtime.IdentityStore.ProvisionWorkspaceIdentityWithExecutor(ctx, tx, request.WorkspaceID, admin, roles, func(stage identitypersistence.WorkspaceIdentityProvisionStage) error {
		if transaction.WorkspaceProvisionFailures == nil {
			return nil
		}
		point := ""
		switch stage {
		case identitypersistence.WorkspaceIdentityProvisionStageUser:
			point = identitysdk.WorkspaceProvisionFailureAfterIdentityUser
		case identitypersistence.WorkspaceIdentityProvisionStageRole:
			point = identitysdk.WorkspaceProvisionFailureAfterIdentityRole
		case identitypersistence.WorkspaceIdentityProvisionStageRoleAssignment:
			point = identitysdk.WorkspaceProvisionFailureAfterRoleAssignment
		}
		if point == "" {
			return nil
		}
		return transaction.WorkspaceProvisionFailures.InjectWorkspaceProvisionFailure(point)
	}); err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, err
	}
	permissionCatalog, err := identityapplication.NewIdentityPermissionCatalogApplicationService(binding.runtime.IdentityStore, binding.runtime.IdentityActions, request.WorkspaceID)
	if err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("assemble workspace Identity permission catalog: %w", err)
	}
	txContext := identitytransaction.WithExecutor(ctx, tx)
	if _, err := permissionCatalog.ReconcileOwner(txContext, identityapplication.IdentityBuiltinAuthorizationOwner); err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("provision workspace Identity permissions: %w", err)
	}
	if err := binding.runtime.AuthStore.UpsertIdentityCredentialWithExecutor(ctx, tx, request.WorkspaceID, identitymodel.IdentityCredential{
		UserID: "admin", PasswordHash: string(passwordHash), MustChangePassword: true,
	}); err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("provision workspace administrator credential: %w", err)
	}
	if transaction.WorkspaceProvisionFailures != nil {
		if err := transaction.WorkspaceProvisionFailures.InjectWorkspaceProvisionFailure(identitysdk.WorkspaceProvisionFailureAfterCredential); err != nil {
			return identitysdk.WorkspaceIdentityProvisionResult{}, err
		}
	}
	return identitysdk.WorkspaceIdentityProvisionResult{
		AdminLoginID: request.AdminLoginID, InitialPassword: password, MustChangePassword: true, ProvisionedRoles: len(roles),
	}, nil
}

func (binding *moduleBinding) ReconcileWorkspaceRoles(ctx context.Context, request identitysdk.WorkspaceRoleReconcileRequest, transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceRoleReconcileResult, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil {
		return identitysdk.WorkspaceRoleReconcileResult{}, &identitysdk.Error{Code: "identity.workspace_role_reconciliation_unavailable"}
	}
	tx, ok := transaction.Native.(*sql.Tx)
	if !ok || tx == nil {
		return identitysdk.WorkspaceRoleReconcileResult{}, &identitysdk.Error{Code: "identity.workspace_provisioning_transaction_required"}
	}
	workspaceID := strings.TrimSpace(request.WorkspaceID)
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return identitysdk.WorkspaceRoleReconcileResult{}, &identitysdk.Error{Code: "identity.workspace_provisioning_invalid", Cause: err}
	}
	roles := binding.provisionedWorkspaceRoles(workspaceID)
	if err := binding.runtime.IdentityStore.UpsertIdentityRolesWithExecutor(ctx, tx, workspaceID, roles); err != nil {
		return identitysdk.WorkspaceRoleReconcileResult{}, fmt.Errorf("reconcile workspace roles: %w", err)
	}
	return identitysdk.WorkspaceRoleReconcileResult{ProvisionedRoles: len(roles)}, nil
}

func (binding *moduleBinding) provisionedWorkspaceRoles(workspaceID string) []identitymodel.IdentityRole {
	definitions := binding.runtime.Identity.PublishedRoleDefinitions(context.Background())
	byKey := map[string]identitymodel.IdentityRole{}
	for _, definition := range definitions {
		key := strings.TrimSpace(definition.Key)
		if key == "" || (key != "admin" && !definition.ProvisionToWorkspaces) {
			continue
		}
		label := strings.TrimSpace(definition.Name)
		if label == "" {
			label = key
		}
		byKey[key] = identitymodel.IdentityRole{ID: identitypersistence.WorkspaceRoleID(workspaceID, key), Key: key, Label: label, Description: "Application-declared tenant login role", Status: identitymodel.IdentityStatusActive}
	}
	if _, found := byKey["admin"]; !found {
		byKey["admin"] = identitymodel.IdentityRole{ID: identitypersistence.WorkspaceRoleID(workspaceID, "admin"), Key: "admin", Label: "Administrator", Description: "Tenant workspace administrator", Status: identitymodel.IdentityStatusActive}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	roles := make([]identitymodel.IdentityRole, 0, len(keys))
	for _, key := range keys {
		roles = append(roles, byKey[key])
	}
	return roles
}

func workspaceInitialPassword() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate initial workspace password: %w", err)
	}
	return "Vd!9" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func validBootstrapInitialPassword(password string) bool {
	if len(password) > 72 || len([]rune(password)) < 12 {
		return false
	}
	var upper, lower, number, symbol bool
	for _, value := range password {
		switch {
		case unicode.IsUpper(value):
			upper = true
		case unicode.IsLower(value):
			lower = true
		case unicode.IsDigit(value):
			number = true
		case unicode.IsPunct(value) || unicode.IsSymbol(value):
			symbol = true
		}
	}
	return upper && lower && number && symbol
}

var _ identitysdk.EmbeddedWorkspaceProvisioner = (*moduleBinding)(nil)
