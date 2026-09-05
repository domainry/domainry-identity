package remotesdk

import (
	"net/http"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// registerRuntimeProjectionRoutes exposes the read-only projection and trusted
// background-principal boundary used by a SaaS Runtime. These routes are never
// reachable with an end-user bearer token or the management Admin middleware.
func registerRuntimeProjectionRoutes(registrar RouteRegistrar, binding identitysdk.Binding, support Support, credentials *ApplicationCredentialRegistry) {
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
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		user, found, err := binding.Projection().FindUser(r.Context(), request)
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
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		organizationUnit, found, err := binding.Projection().FindOrganizationUnit(r.Context(), request)
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
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		resolver, ok := binding.Projection().(identitysdk.DisplayNameProjection)
		if !ok {
			support.writeServiceError(w, r, &identitysdk.Error{Code: "identity.display_name_projection_unavailable"})
			return
		}
		result, err := resolver.ResolveDisplayNames(r.Context(), request)
		writeRuntimeProjection(w, r, result, err, support)
	})
	registrar.HandleFunc("POST /identity/users/query", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeProjectionQuery(w, r)
		if !ok {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Projection().ListUsers(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/roles/query", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeProjectionQuery(w, r)
		if !ok {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Projection().ListRoles(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/user-role-assignments/query", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.UserRoleAssignmentQuery
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Projection().ListUserRoleAssignments(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/principal/resolve", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.PrincipalResolutionRequest
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		resolution, err := binding.Principals().Resolve(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, resolution)
	})
}

func writeRuntimeProjection[T any](w http.ResponseWriter, r *http.Request, value T, err error, support Support) {
	if err != nil {
		support.writeServiceError(w, r, err)
		return
	}
	support.writeJSON(w, http.StatusOK, value)
}
