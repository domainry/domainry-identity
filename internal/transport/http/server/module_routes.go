package httpserver

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/domainry/domainry-foundation/modulehttp"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func registerModuleRoutes(registrar interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}, providers []modulehttp.Provider, support *httpSupport) error {
	if registrar == nil || support == nil {
		return fmt.Errorf("module HTTP route host is unavailable")
	}
	for _, provider := range providers {
		if provider == nil {
			return fmt.Errorf("module HTTP surface provider is required")
		}
		for _, surface := range provider.HTTPSurfaces() {
			if err := modulehttp.ValidateSurface(surface); err != nil {
				return fmt.Errorf("validate module HTTP surface: %w", err)
			}
			expectedOwner := "module:" + strings.TrimSpace(surface.Owner())
			for _, declared := range surface.Routes() {
				route := declared
				if strings.TrimSpace(route.Action.Owner) != expectedOwner {
					return fmt.Errorf("module HTTP surface %q action %q owner=%q want=%q", surface.Owner(), route.Action.Key, route.Action.Owner, expectedOwner)
				}
				next := surface.Handler()
				registrar.HandleFunc(route.Pattern(), support.action(route.Action.Key, func(w http.ResponseWriter, r *http.Request) {
					principal := identityModuleSDKPrincipal(support.principal(r), route.Action.Key)
					token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
					ctx := identitysdk.WithRequestIdentity(r.Context(), identitysdk.RequestIdentity{Principal: principal, AccessToken: token})
					next.ServeHTTP(w, r.WithContext(ctx))
				}))
			}
		}
	}
	return nil
}

func identityModuleSDKPrincipal(principal identitymodel.Principal, actionKey string) identitysdk.Principal {
	grants := []identitysdk.FunctionGrant{}
	dataPolicies := []identitysdk.DataPolicy{}
	permissions := []string{}
	actionKey = strings.TrimSpace(actionKey)
	separator := strings.LastIndexByte(actionKey, '.')
	if separator > 0 && separator < len(actionKey)-1 && identitycontract.IdentityRoleHasPermissionKey(principal.Role, actionKey) {
		resource, action := actionKey[:separator], actionKey[separator+1:]
		grants = append(grants, identitysdk.FunctionGrant{Resource: identitysdk.ResourceType(resource), Action: identitysdk.Action(action), Effect: identitysdk.EffectAllow})
		for index, permission := range identitymodel.RolePermissionsForKey(principal.Role.Permissions, actionKey) {
			dataPolicies = append(dataPolicies, identitysdk.DataPolicy{
				Key: "module-" + actionKey + "-" + strconv.Itoa(index), Resource: identitysdk.ResourceType(resource), Action: identitysdk.Action(action), Effect: identitysdk.EffectAllow,
				DataScopes: []identitysdk.DataScope{identitysdk.DataScope(permission.DataScope)}, Predicate: identityModuleDataScopePredicate(permission.DataScope),
			})
		}
		permissions = append(permissions, actionKey)
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: identitysdk.AuthorizationRevision(principal.AuthorizationRevision),
		Subject: identitysdk.Subject{WorkspaceID: identitysdk.WorkspaceID(principal.WorkspaceID), SubjectID: identitysdk.SubjectID(principal.UserID), OrgID: principal.OrgID, OrgScopeIDs: append([]string(nil), principal.OrgScopeIDs...), SupportOrgID: principal.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), principal.SupportOrgScopeIDs...)}, FunctionGrants: grants, DataPolicies: dataPolicies,
	}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: principal.Known,
		WorkspaceID: principal.WorkspaceID, UserID: principal.UserID, RoleKey: principal.Role.Key,
		AuthorizationRevision: principal.AuthorizationRevision, OrgID: principal.OrgID, OrgScopeIDs: append([]string(nil), principal.OrgScopeIDs...), SupportOrgID: principal.SupportOrgID, SupportOrgScopeIDs: append([]string(nil), principal.SupportOrgScopeIDs...), ReportingScopeUserIDs: append([]string(nil), principal.ReportingScopeUserIDs...), Permissions: permissions, AccessBundle: &bundle,
	}
}

func identityModuleDataScopePredicate(scope identitymodel.IdentityDataScope) identitysdk.Predicate {
	switch scope {
	case identitymodel.IdentityDataScopeOwner:
		return identitysdk.Predicate{Fact: "owner_user_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"}
	case identitymodel.IdentityDataScopeOrg:
		return identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorEqual, Value: "$subject.org_id"}
	case identitymodel.IdentityDataScopeOrgChild:
		return identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.org_scope_ids"}
	case identitymodel.IdentityDataScopeTargetOrg:
		return identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.support_org_scope_ids"}
	default:
		return identitysdk.Predicate{}
	}
}
