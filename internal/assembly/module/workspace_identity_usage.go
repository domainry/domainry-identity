package moduleassembly

import (
	"context"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitymodulehost "github.com/domainry/domainry-identity-sdk/modulehost"
	identityapplication "github.com/domainry/domainry-identity/internal/application/identity"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
)

type moduleWorkspaceIdentityUsage struct {
	binding *moduleBinding
	tx      identitytransaction.Executor
}

type moduleWorkspaceIdentityUsageBinder struct {
	binding *moduleBinding
}

func (binder moduleWorkspaceIdentityUsageBinder) AuthorizeWorkspaceIdentityUsage(ctx context.Context, request identitysdk.WorkspaceIdentityUsageAuthorizationRequest) (identitysdk.WorkspaceIdentityUsageAuthorization, error) {
	if binder.binding == nil || binder.binding.workspaceUsage == nil {
		return identitysdk.WorkspaceIdentityUsageAuthorization{}, &identitysdk.Error{Code: "identity.workspace_usage_authority_required"}
	}
	grant, err := binder.binding.workspaceUsage.Authorize(ctx, request.AccessToken)
	if err != nil {
		return identitysdk.WorkspaceIdentityUsageAuthorization{}, err
	}
	return workspaceIdentityUsageAuthorizationToSDK(grant), nil
}

func (binding *moduleBinding) WorkspaceIdentityUsageUnitOfWorkBinder() identitysdk.WorkspaceIdentityUsageUnitOfWorkBinder {
	return moduleWorkspaceIdentityUsageBinder{binding: binding}
}

func (binder moduleWorkspaceIdentityUsageBinder) BindWorkspaceIdentityUsageUnitOfWork(transaction identitysdk.EmbeddedTransaction) (identitysdk.WorkspaceIdentityUsageAggregate, error) {
	tx, ok := embeddedTransactionExecutor(transaction)
	if !ok {
		return nil, &identitysdk.Error{Code: "identity.workspace_usage_transaction_required"}
	}
	if binder.binding == nil || binder.binding.workspaceUsage == nil {
		return nil, &identitysdk.Error{Code: "identity.workspace_usage_authority_required"}
	}
	return moduleWorkspaceIdentityUsage{binding: binder.binding, tx: tx}, nil
}

func (adapter moduleWorkspaceIdentityUsage) ListWorkspaceIdentityUsage(ctx context.Context, request identitysdk.WorkspaceIdentityUsageRequest) (identitysdk.WorkspaceIdentityUsagePage, error) {
	if adapter.binding == nil || adapter.binding.workspaceUsage == nil || adapter.tx == nil {
		return identitysdk.WorkspaceIdentityUsagePage{}, &identitysdk.Error{Code: "identity.workspace_usage_unavailable"}
	}
	page, err := adapter.binding.workspaceUsage.List(identitytransaction.WithExecutor(ctx, adapter.tx), identityapplication.IdentityWorkspaceUsageRequest{
		ContractVersion: request.ContractVersion,
		ContractHash:    request.ContractHash,
		Authorization:   workspaceIdentityUsageAuthorizationFromSDK(request.Authorization),
		AccessToken:     request.AccessToken,
		PageSize:        request.PageSize,
		Cursor:          request.Cursor,
	})
	if err != nil {
		return identitysdk.WorkspaceIdentityUsagePage{}, err
	}
	result := identitysdk.WorkspaceIdentityUsagePage{NextCursor: page.NextCursor, Items: make([]identitysdk.WorkspaceIdentityUsage, len(page.Items))}
	for index, item := range page.Items {
		result.Items[index] = identitysdk.WorkspaceIdentityUsage{
			WorkspaceID: item.WorkspaceID,
			Accounts: identitysdk.WorkspaceIdentityAccountCounts{
				ActiveHumanAccounts:               item.Accounts.ActiveHumanAccounts,
				ActiveHumanAccountsWithActiveRole: item.Accounts.ActiveHumanAccountsWithActiveRole,
				DisabledHumanAccounts:             item.Accounts.DisabledHumanAccounts,
				ServiceAccounts:                   item.Accounts.ServiceAccounts,
				AutomationAccounts:                item.Accounts.AutomationAccounts,
			},
		}
	}
	return result, nil
}

func (adapter moduleWorkspaceIdentityUsage) ResolveWorkspaceIdentityUsage(ctx context.Context, request identitysdk.WorkspaceIdentityUsageResolveRequest) (identitysdk.WorkspaceIdentityUsage, error) {
	if adapter.binding == nil || adapter.binding.workspaceUsage == nil || adapter.tx == nil {
		return identitysdk.WorkspaceIdentityUsage{}, &identitysdk.Error{Code: "identity.workspace_usage_unavailable"}
	}
	item, err := adapter.binding.workspaceUsage.Resolve(identitytransaction.WithExecutor(ctx, adapter.tx), identityapplication.IdentityWorkspaceUsageResolveRequest{
		ContractVersion: request.ContractVersion,
		ContractHash:    request.ContractHash,
		Authorization:   workspaceIdentityUsageAuthorizationFromSDK(request.Authorization),
		AccessToken:     request.AccessToken,
		WorkspaceCode:   request.WorkspaceCode,
	})
	if err != nil {
		return identitysdk.WorkspaceIdentityUsage{}, err
	}
	return identitysdk.WorkspaceIdentityUsage{
		WorkspaceID: item.WorkspaceID,
		Accounts: identitysdk.WorkspaceIdentityAccountCounts{
			ActiveHumanAccounts:               item.Accounts.ActiveHumanAccounts,
			ActiveHumanAccountsWithActiveRole: item.Accounts.ActiveHumanAccountsWithActiveRole,
			DisabledHumanAccounts:             item.Accounts.DisabledHumanAccounts,
			ServiceAccounts:                   item.Accounts.ServiceAccounts,
			AutomationAccounts:                item.Accounts.AutomationAccounts,
		},
	}, nil
}

func workspaceIdentityUsageAuthorizationToSDK(grant identitymodel.IdentityWorkspaceUsageGrant) identitysdk.WorkspaceIdentityUsageAuthorization {
	return identitysdk.WorkspaceIdentityUsageAuthorization{
		InstallationID: grant.InstallationID, ApplicationKey: grant.ApplicationKey, SubjectID: grant.SubjectID,
		AuditWorkspaceID: grant.AuditWorkspaceID, PermissionKey: grant.PermissionKey, AuthorizationRevision: grant.AuthorizationRevision,
		AuthorizationAuditID: grant.AuthorizationAuditID,
	}
}

func workspaceIdentityUsageAuthorizationFromSDK(grant identitysdk.WorkspaceIdentityUsageAuthorization) identitymodel.IdentityWorkspaceUsageGrant {
	return identitymodel.IdentityWorkspaceUsageGrant{
		InstallationID: grant.InstallationID, ApplicationKey: grant.ApplicationKey, SubjectID: grant.SubjectID,
		AuditWorkspaceID: grant.AuditWorkspaceID, PermissionKey: grant.PermissionKey, AuthorizationRevision: grant.AuthorizationRevision,
		AuthorizationAuditID: grant.AuthorizationAuditID,
	}
}

type moduleWorkspaceIdentityUsageAuthority struct {
	authority identitymodulehost.WorkspaceIdentityUsageInstallationAuthority
}

func (adapter moduleWorkspaceIdentityUsageAuthority) AuthorizeWorkspaceIdentityUsage(ctx context.Context, accessToken, permissionKey string) (identitymodel.IdentityWorkspaceUsageGrant, error) {
	grant, err := adapter.authority.AuthorizeWorkspaceIdentityUsage(ctx, identitymodulehost.WorkspaceIdentityUsageAuthorizationRequest{
		AccessToken: accessToken, PermissionKey: permissionKey,
	})
	if err != nil {
		return identitymodel.IdentityWorkspaceUsageGrant{}, err
	}
	return identitymodel.IdentityWorkspaceUsageGrant{
		InstallationID: grant.InstallationID, ApplicationKey: grant.ApplicationKey, SubjectID: grant.SubjectID,
		AuditWorkspaceID: grant.AuditWorkspaceID, PermissionKey: grant.PermissionKey, AuthorizationRevision: grant.AuthorizationRevision,
		AuthorizationAuditID: grant.AuthorizationAuditID,
	}, nil
}

func (adapter moduleWorkspaceIdentityUsageAuthority) ListAuthorizedWorkspaceIdentityUsage(ctx context.Context, grant identitymodel.IdentityWorkspaceUsageGrant, afterWorkspaceID string, limit int, expectedCatalogRevision string) (identitymodel.IdentityWorkspaceUsageCatalogPage, error) {
	page, err := adapter.authority.ListAuthorizedWorkspaceIdentityUsage(ctx, identitymodulehost.WorkspaceIdentityUsageGrant{
		InstallationID: grant.InstallationID, ApplicationKey: grant.ApplicationKey, SubjectID: grant.SubjectID,
		AuditWorkspaceID: grant.AuditWorkspaceID, PermissionKey: grant.PermissionKey, AuthorizationRevision: grant.AuthorizationRevision,
		AuthorizationAuditID: grant.AuthorizationAuditID,
	}, identitymodulehost.WorkspaceIdentityUsageCatalogQuery{
		AfterWorkspaceID: afterWorkspaceID, Limit: limit, ExpectedCatalogRevision: expectedCatalogRevision,
	})
	if err != nil {
		return identitymodel.IdentityWorkspaceUsageCatalogPage{}, err
	}
	result := identitymodel.IdentityWorkspaceUsageCatalogPage{CatalogRevision: page.CatalogRevision, Workspaces: make([]identitymodel.IdentityWorkspaceUsageCatalogEntry, len(page.Workspaces))}
	for index, workspace := range page.Workspaces {
		result.Workspaces[index] = identitymodel.IdentityWorkspaceUsageCatalogEntry{
			WorkspaceID: workspace.WorkspaceID, Status: string(workspace.Status), Known: workspace.Known, Authorized: workspace.Authorized,
		}
	}
	return result, nil
}

func (adapter moduleWorkspaceIdentityUsageAuthority) ResolveAuthorizedWorkspaceIdentityUsage(ctx context.Context, grant identitymodel.IdentityWorkspaceUsageGrant, workspaceCode string) (identitymodel.IdentityWorkspaceUsageCatalogEntry, error) {
	workspace, err := adapter.authority.ResolveAuthorizedWorkspaceIdentityUsage(ctx, identitymodulehost.WorkspaceIdentityUsageGrant{
		InstallationID: grant.InstallationID, ApplicationKey: grant.ApplicationKey, SubjectID: grant.SubjectID,
		AuditWorkspaceID: grant.AuditWorkspaceID, PermissionKey: grant.PermissionKey, AuthorizationRevision: grant.AuthorizationRevision,
		AuthorizationAuditID: grant.AuthorizationAuditID,
	}, identitymodulehost.WorkspaceIdentityUsageCatalogResolve{WorkspaceCode: workspaceCode})
	if err != nil {
		return identitymodel.IdentityWorkspaceUsageCatalogEntry{}, err
	}
	return identitymodel.IdentityWorkspaceUsageCatalogEntry{
		WorkspaceID: workspace.WorkspaceID, Status: string(workspace.Status), Known: workspace.Known, Authorized: workspace.Authorized,
	}, nil
}

var _ identitysdk.WorkspaceIdentityUsageAggregate = moduleWorkspaceIdentityUsage{}
var _ identitysdk.WorkspaceIdentityUsageUnitOfWorkBinder = moduleWorkspaceIdentityUsageBinder{}
