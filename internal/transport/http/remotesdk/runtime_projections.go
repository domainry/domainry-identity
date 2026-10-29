package remotesdk

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
)

// registerRuntimeProjectionRoutes exposes the read-only projection and trusted
// background-principal boundary used by a SaaS Runtime. These routes are never
// reachable with an end-user bearer token or the management Admin middleware.
func registerRuntimeProjectionRoutes(registrar RouteRegistrar, binding identitysdk.Binding, support Support, credentials *ApplicationCredentialRegistry, browserApplications ...*BrowserApplicationRegistry) {
	var browserRegistry *BrowserApplicationRegistry
	if len(browserApplications) > 0 {
		browserRegistry = browserApplications[0]
	}
	decodeProjectionQuery := func(w http.ResponseWriter, r *http.Request) (identitysdk.ProjectionQuery, bool) {
		var request identitysdk.ProjectionQuery
		if !support.decodeJSON(w, r, &request) {
			return identitysdk.ProjectionQuery{}, false
		}
		return request, true
	}
	registrar.HandleFunc("POST /identity/users/lookup", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.UserLookup
		if !support.decodeJSON(w, r, &request) {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		user, found, err := binding.Projection().FindUser(runtimeApplicationContext(r, scope), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, struct {
			User  identitysdk.User `json:"user"`
			Found bool             `json:"found"`
		}{User: user, Found: found})
	})
	registrar.HandleFunc("POST /identity/organization-units/lookup", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.OrganizationUnitLookup
		if !support.decodeJSON(w, r, &request) {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		organizationUnit, found, err := binding.Projection().FindOrganizationUnit(runtimeApplicationContext(r, scope), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, struct {
			OrganizationUnit identitysdk.OrganizationUnit `json:"organization_unit"`
			Found            bool                         `json:"found"`
		}{OrganizationUnit: organizationUnit, Found: found})
	})
	registrar.HandleFunc("POST /identity/display-names/resolve", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.DisplayNameQuery
		if !support.decodeJSON(w, r, &request) {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		resolver, ok := binding.Projection().(identitysdk.DisplayNameProjection)
		if !ok {
			support.writeServiceError(w, r, &identitysdk.Error{Class: identitysdk.ErrorClassUnavailable, Code: "identity.display_name_projection_unavailable"})
			return
		}
		result, err := resolver.ResolveDisplayNames(runtimeApplicationContext(r, scope), request)
		writeRuntimeProjection(w, r, result, err, support)
	})
	registrar.HandleFunc("POST /identity/users/query", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeProjectionQuery(w, r)
		if !ok {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		values, err := binding.Projection().ListUsers(runtimeApplicationContext(r, scope), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/roles/query", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeProjectionQuery(w, r)
		if !ok {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		values, err := binding.Projection().ListRoles(runtimeApplicationContext(r, scope), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/user-role-assignments/query", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.UserRoleAssignmentQuery
		if !support.decodeJSON(w, r, &request) {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		values, err := binding.Projection().ListUserRoleAssignments(runtimeApplicationContext(r, scope), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/principal/resolve", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.PrincipalResolutionRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		scope := runtimeApplicationScope(r)
		if !authorizeRuntimeApplicationCredential(w, r, support, credentials, browserRegistry, scope) {
			return
		}
		resolution, err := binding.Principals().Resolve(runtimeApplicationContext(r, scope), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, resolution)
	})
}

// authorizeRuntimeApplicationCredential accepts either a tenant-scoped
// Runtime credential or the confidential credential of a registered global
// SaaS application. The latter is application-scoped and may operate on the
// explicitly supplied Workspace for Runtime service boundaries; catalog
// publication remains independently constrained by source-owner policy.
func authorizeRuntimeApplicationCredential(w http.ResponseWriter, r *http.Request, support Support, credentials *ApplicationCredentialRegistry, browserApplications *BrowserApplicationRegistry, scope identitysdk.ApplicationScope) bool {
	if credentials != nil {
		decision := credentials.Authorize(r.Header.Get("Authorization"), scope)
		if decision.Authenticated {
			writeApplicationCredentialRateLimit(w, decision)
			if decision.RateLimited {
				support.writeError(w, r, http.StatusTooManyRequests, "identity.application_rate_limited")
				return false
			}
			return true
		}
	}
	if browserApplications != nil && scope.WorkspaceID.Valid() && browserApplications.Authorize(r.Header.Get("Authorization"), scope.ApplicationKey) {
		return true
	}
	support.writeError(w, r, http.StatusUnauthorized, "identity.service_credential_required")
	return false
}

func runtimeApplicationScope(r *http.Request) identitysdk.ApplicationScope {
	workspaceID := strings.TrimSpace(r.Header.Get("X-Domainry-Workspace-ID"))
	if workspaceID == "" {
		workspaceID = strings.TrimSpace(r.Header.Get("X-Workspace-ID"))
	}
	return identitysdk.ApplicationScope{

		WorkspaceID:    identitysdk.WorkspaceID(workspaceID),
		ApplicationKey: identitysdk.ApplicationKey(strings.TrimSpace(r.Header.Get("X-Domainry-Application-Key"))),
	}
}

func runtimeApplicationContext(r *http.Request, scope identitysdk.ApplicationScope) context.Context {
	ctx := requestcontext.WithWorkspaceID(r.Context(), string(scope.WorkspaceID))
	return identityscope.WithScope(ctx, scope)
}

func writeRuntimeProjection[T any](w http.ResponseWriter, r *http.Request, value T, err error, support Support) {
	if err != nil {
		support.writeServiceError(w, r, err)
		return
	}
	support.writeJSON(w, http.StatusOK, value)
}
