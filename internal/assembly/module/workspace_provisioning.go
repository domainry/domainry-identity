package moduleassembly

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"golang.org/x/crypto/bcrypt"
)

func (binding *moduleBinding) ProvisionWorkspaceIdentity(ctx context.Context, request identitysdk.WorkspaceIdentityProvisionRequest, transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceIdentityProvisionResult, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil || binding.runtime.IdentityActions == nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.workspace_provisioning_unavailable"}
	}
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassInternal, Code: "identity.workspace_provisioning_transaction_required"}
	}
	request.WorkspaceID = strings.TrimSpace(request.WorkspaceID)
	request.AdminLoginID = strings.ToLower(strings.TrimSpace(request.AdminLoginID))
	request.AdminName = strings.TrimSpace(request.AdminName)
	if _, err := identitymodel.NewWorkspaceID(request.WorkspaceID); err != nil || request.AdminLoginID == "" || request.AdminName == "" {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.workspace_provisioning_invalid", Cause: err}
	}
	password := request.InitialPassword
	if password == "" {
		var err error
		password, err = workspaceInitialPassword()
		if err != nil {
			return identitysdk.WorkspaceIdentityProvisionResult{}, err
		}
	} else if !validBootstrapInitialPassword(password) {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.workspace_provisioning_initial_password_invalid"}
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("hash initial workspace password: %w", err)
	}
	roles, err := binding.runtime.IdentityStore.ListIdentityRoles(ctx, request.WorkspaceID)
	if err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("load global roles for workspace provisioning: %w", err)
	}
	organizations, users, assignments, credentials, err := acceptanceFixtures(request, roles)
	if err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, err
	}
	admin := identitymodel.IdentityUser{
		UserID: "admin", Name: request.AdminName, Email: request.AdminLoginID,
		AccountType: identitymodel.IdentityAccountHuman, Status: identitymodel.IdentityStatusActive,
	}
	adminRoleID := ""
	for _, role := range roles {
		if role.ScopeType == identitymodel.IdentityRoleScopeGlobal && role.Key == "admin" && role.Status == identitymodel.IdentityStatusActive {
			adminRoleID = role.RoleID
			break
		}
	}
	if adminRoleID == "" {
		return identitysdk.WorkspaceIdentityProvisionResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.global_administrator_role_unavailable"}
	}
	if err := binding.runtime.IdentityStore.ProvisionWorkspaceIdentityWithExecutor(ctx, tx, request.WorkspaceID, admin, nil, organizations, users, assignments, adminRoleID, func(stage identitypersistence.WorkspaceIdentityProvisionStage) error {
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
	if err := binding.runtime.AuthStore.UpsertIdentityCredentialWithExecutor(ctx, tx, request.WorkspaceID, identitymodel.IdentityCredential{
		UserID: "admin", PasswordHash: string(passwordHash), MustChangePassword: binding.initialCredentialRotationRequired(),
	}); err != nil {
		return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("provision workspace administrator credential: %w", err)
	}
	for _, credential := range credentials {
		if err := binding.runtime.AuthStore.UpsertIdentityCredentialWithExecutor(ctx, tx, request.WorkspaceID, credential); err != nil {
			return identitysdk.WorkspaceIdentityProvisionResult{}, fmt.Errorf("provision acceptance actor credential: %w", err)
		}
	}
	if transaction.WorkspaceProvisionFailures != nil {
		if err := transaction.WorkspaceProvisionFailures.InjectWorkspaceProvisionFailure(identitysdk.WorkspaceProvisionFailureAfterCredential); err != nil {
			return identitysdk.WorkspaceIdentityProvisionResult{}, err
		}
	}
	return identitysdk.WorkspaceIdentityProvisionResult{
		AdminLoginID: request.AdminLoginID, InitialPassword: password, MustChangePassword: binding.initialCredentialRotationRequired(), ProvisionedRoles: 0,
	}, nil
}

func acceptanceFixtures(request identitysdk.WorkspaceIdentityProvisionRequest, roles []identitymodel.IdentityRole) ([]identitymodel.IdentityOrganizationUnit, []identitymodel.IdentityUser, []identitymodel.IdentityUserRoleAssignment, []identitymodel.IdentityCredential, error) {
	roleIDs := map[string]string{}
	for _, role := range roles {
		roleIDs[strings.TrimSpace(role.Key)] = role.RoleID
	}
	organizations := make([]identitymodel.IdentityOrganizationUnit, 0, len(request.AcceptanceOrganizations))
	organizationIDs := map[string]bool{}
	for index, item := range request.AcceptanceOrganizations {
		id, code, name := strings.TrimSpace(item.ID), strings.TrimSpace(item.Code), strings.TrimSpace(item.Name)
		if id == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("organization", index, "id", "required", nil)
		}
		if organizationIDs[id] {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("organization", index, "id", "duplicate", map[string]string{"organization_id": id})
		}
		if code == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("organization", index, "code", "required", map[string]string{"organization_id": id})
		}
		if name == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("organization", index, "name", "required", map[string]string{"organization_id": id})
		}
		organizationIDs[id] = true
		organizations = append(organizations, identitymodel.IdentityOrganizationUnit{OrganizationUnitID: id, Code: code, Name: name, NodeType: identitymodel.IdentityOrganizationUnitDepartment, Path: "/" + id, AncestorIDs: []string{}, Depth: 0, SortOrder: index, Status: identitymodel.IdentityStatusActive})
	}
	users := make([]identitymodel.IdentityUser, 0, len(request.AcceptanceActors))
	assignments := make([]identitymodel.IdentityUserRoleAssignment, 0, len(request.AcceptanceActors))
	credentials := make([]identitymodel.IdentityCredential, 0, len(request.AcceptanceActors))
	userIDs := map[string]bool{}
	for index, actor := range request.AcceptanceActors {
		id, loginID, name := strings.TrimSpace(actor.ID), strings.ToLower(strings.TrimSpace(actor.LoginID)), strings.TrimSpace(actor.Name)
		roleKey := strings.TrimSpace(actor.RoleKey)
		organizationID, managerUserID := strings.TrimSpace(actor.OrganizationID), strings.TrimSpace(actor.ManagerUserID)
		roleID, roleFound := roleIDs[roleKey]
		if id == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "id", "required", nil)
		}
		if userIDs[id] {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "id", "duplicate", map[string]string{"actor_id": id})
		}
		if loginID == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "login_id", "required", map[string]string{"actor_id": id})
		}
		if name == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "name", "required", map[string]string{"actor_id": id})
		}
		if roleKey == "" {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "role_key", "required", map[string]string{"actor_id": id})
		}
		if !roleFound {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "role_key", "unknown", map[string]string{"actor_id": id, "role_key": roleKey})
		}
		if organizationID != "" && !organizationIDs[organizationID] {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "organization_id", "unknown", map[string]string{"actor_id": id, "organization_id": organizationID})
		}
		if !validBootstrapInitialPassword(actor.InitialPassword) {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "initial_password", "policy_violation", map[string]string{"actor_id": id})
		}
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(actor.InitialPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("hash acceptance actor password: %w", err)
		}
		userIDs[id] = true
		users = append(users, identitymodel.IdentityUser{UserID: id, Name: name, Email: loginID, AccountType: identitymodel.IdentityAccountHuman, OrgID: organizationID, ManagerUserID: managerUserID, ReportingPath: acceptanceReportingPath(id, managerUserID), Status: identitymodel.IdentityStatusActive})
		assignments = append(assignments, identitymodel.IdentityUserRoleAssignment{UserID: id, RoleID: roleID, Source: "runtime_acceptance_fixture", Status: "active"})
		credentials = append(credentials, identitymodel.IdentityCredential{UserID: id, PasswordHash: string(passwordHash), MustChangePassword: false})
	}
	for index, user := range users {
		if user.ManagerUserID != "" && !userIDs[user.ManagerUserID] {
			return nil, nil, nil, nil, acceptanceFixtureInvalid("actor", index, "manager_user_id", "unknown", map[string]string{"actor_id": user.UserID, "manager_user_id": user.ManagerUserID})
		}
	}
	return organizations, users, assignments, credentials, nil
}

func (binding *moduleBinding) ProvisionWorkspaceAcceptanceFixtures(ctx context.Context, request identitysdk.WorkspaceAcceptanceFixtureRequest, transaction identitysdk.EmbeddedTransaction) error {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil {
		return &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.workspace_acceptance_fixture_unavailable"}
	}
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return &identitysdk.Error{Class: identitysdk.ErrorClassInternal, Code: "identity.workspace_provisioning_transaction_required"}
	}
	request.WorkspaceID = strings.TrimSpace(request.WorkspaceID)
	if _, err := identitymodel.NewWorkspaceID(request.WorkspaceID); err != nil {
		return &identitysdk.Error{Class: identitysdk.ErrorClassInternal, Code: "identity.workspace_acceptance_fixture_invalid", Cause: err}
	}
	if len(request.Organizations) == 0 && len(request.Actors) == 0 {
		return nil
	}
	allRoles, err := binding.runtime.IdentityStore.ListIdentityRoles(ctx, request.WorkspaceID)
	if err != nil {
		return err
	}
	organizations, users, assignments, credentials, err := acceptanceFixtures(identitysdk.WorkspaceIdentityProvisionRequest{
		WorkspaceID: request.WorkspaceID, AcceptanceOrganizations: request.Organizations, AcceptanceActors: request.Actors,
	}, allRoles)
	if err != nil {
		return err
	}
	if err := binding.runtime.IdentityStore.ProvisionWorkspaceAcceptanceFixturesWithExecutor(ctx, tx, request.WorkspaceID, nil, organizations, users, assignments); err != nil {
		return err
	}
	for _, credential := range credentials {
		if err := binding.runtime.AuthStore.UpsertIdentityCredentialWithExecutor(ctx, tx, request.WorkspaceID, credential); err != nil {
			return fmt.Errorf("provision acceptance actor credential: %w", err)
		}
	}
	return nil
}

func acceptanceFixtureInvalid(kind string, index int, field, reason string, values map[string]string) *identitysdk.Error {
	params := map[string]string{
		"fixture_kind":  kind,
		"fixture_index": strconv.Itoa(index),
		"field":         field,
		"reason":        reason,
	}
	for key, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			params[key] = value
		}
	}
	return &identitysdk.Error{
		Class:   identitysdk.ErrorClassInternal,
		Code:    "identity.workspace_acceptance_fixture_invalid",
		Message: fmt.Sprintf("%s[%d].%s reason=%s", kind, index, field, reason),
		Params:  params,
	}
}

func acceptanceReportingPath(userID, managerUserID string) string {
	if managerUserID == "" {
		return "/" + userID
	}
	return "/" + managerUserID + "/" + userID
}

func (binding *moduleBinding) ReconcileWorkspaceRoles(ctx context.Context, request identitysdk.WorkspaceRoleReconcileRequest, transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceRoleReconcileResult, error) {
	if binding == nil || binding.runtime == nil || binding.runtime.Identity == nil || binding.runtime.IdentityStore == nil {
		return identitysdk.WorkspaceRoleReconcileResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.workspace_role_reconciliation_unavailable"}
	}
	_, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return identitysdk.WorkspaceRoleReconcileResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassInternal, Code: "identity.workspace_provisioning_transaction_required"}
	}
	workspaceID := strings.TrimSpace(request.WorkspaceID)
	if _, err := identitymodel.NewWorkspaceID(workspaceID); err != nil {
		return identitysdk.WorkspaceRoleReconcileResult{}, &identitysdk.Error{Class: identitysdk.ErrorClassBadRequest, Code: "identity.workspace_provisioning_invalid", Cause: err}
	}
	return identitysdk.WorkspaceRoleReconcileResult{ProvisionedRoles: 0}, nil
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
var _ identitysdk.EmbeddedWorkspaceAcceptanceFixtureProvisioner = (*moduleBinding)(nil)
var _ identitysdk.BootstrapBinding = (*moduleBinding)(nil)
