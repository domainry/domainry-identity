package httpserver

import (
	"fmt"
	"net/http"
	"strings"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-foundation/modulehttp"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func registerAuditRoutes(mux *http.ServeMux, binding auditsdk.Binding, support *httpSupport) error {
	provider, ok := binding.(modulehttp.Provider)
	if !ok {
		return fmt.Errorf("Audit Binding does not provide HTTP surfaces")
	}
	var surface modulehttp.Surface
	for _, candidate := range provider.HTTPSurfaces() {
		if candidate != nil && candidate.Owner() == "audit" && candidate.Name() == "product" {
			surface = candidate
			break
		}
	}
	if surface == nil {
		return fmt.Errorf("Audit product HTTP surface is unavailable")
	}
	if err := modulehttp.ValidateSurface(surface); err != nil {
		return fmt.Errorf("validate Audit product HTTP surface: %w", err)
	}
	routes := make(map[string]modulehttp.Route, len(surface.Routes()))
	for _, route := range surface.Routes() {
		routes[route.Pattern] = route
	}
	for _, pattern := range []string{"GET /tenant-admin/audit-events", "GET /tenant-admin/audit-events/export"} {
		if _, exists := routes[pattern]; !exists {
			return fmt.Errorf("Audit product HTTP surface is missing %q", pattern)
		}
		next := surface.Handler()
		mux.HandleFunc(pattern, support.admin(func(w http.ResponseWriter, r *http.Request) {
			principal := identityAuditSDKPrincipal(support.principal(r))
			token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			ctx := identitysdk.WithRequestIdentity(r.Context(), identitysdk.RequestIdentity{Principal: principal, AccessToken: token})
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
	return nil
}

func identityAuditSDKPrincipal(principal identitymodel.Principal) identitysdk.Principal {
	grants := make([]identitysdk.FunctionGrant, 0, 2)
	for _, permission := range []string{"audit.governance.read", "audit.governance.export"} {
		if !identitycontract.IdentityRoleHasPermissionKey(principal.Role, permission) {
			continue
		}
		separator := strings.LastIndexByte(permission, '.')
		grants = append(grants, identitysdk.FunctionGrant{Resource: identitysdk.ResourceType(permission[:separator]), Action: identitysdk.Action(permission[separator+1:]), Effect: identitysdk.EffectAllow})
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: identitysdk.AuthorizationRevision(principal.AuthorizationRevision),
		Subject: identitysdk.Subject{WorkspaceID: identitysdk.WorkspaceID(principal.WorkspaceID), SubjectID: identitysdk.SubjectID(principal.UserID)}, FunctionGrants: grants,
	}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: principal.Known,
		WorkspaceID: principal.WorkspaceID, UserID: principal.UserID, RoleKey: principal.Role.Key,
		AuthorizationRevision: principal.AuthorizationRevision, Permissions: append([]string(nil), principal.Role.Permissions...), AccessBundle: &bundle,
	}
}
