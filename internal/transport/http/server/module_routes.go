package httpserver

import (
	"fmt"
	"net/http"
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
	permissions := []string{}
	actionKey = strings.TrimSpace(actionKey)
	separator := strings.LastIndexByte(actionKey, '.')
	if separator > 0 && separator < len(actionKey)-1 && identitycontract.IdentityRoleHasPermissionKey(principal.Role, actionKey) {
		grants = append(grants, identitysdk.FunctionGrant{Resource: identitysdk.ResourceType(actionKey[:separator]), Action: identitysdk.Action(actionKey[separator+1:]), Effect: identitysdk.EffectAllow})
		permissions = append(permissions, actionKey)
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: identitysdk.AuthorizationRevision(principal.AuthorizationRevision),
		Subject: identitysdk.Subject{WorkspaceID: identitysdk.WorkspaceID(principal.WorkspaceID), SubjectID: identitysdk.SubjectID(principal.UserID)}, FunctionGrants: grants,
	}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: principal.Known,
		WorkspaceID: principal.WorkspaceID, UserID: principal.UserID, RoleKey: principal.Role.Key,
		AuthorizationRevision: principal.AuthorizationRevision, Permissions: permissions, AccessBundle: &bundle,
	}
}
