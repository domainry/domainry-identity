package remotesdk

import (
	"net/http"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// registerRuntimeProjectionRoutes exposes the read-only directory and trusted
// background-principal boundary used by a SaaS Runtime. These routes are never
// reachable with an end-user bearer token or the management Admin middleware.
func registerRuntimeProjectionRoutes(registrar RouteRegistrar, binding identitysdk.Binding, support Support, credentials *ApplicationCredentialRegistry) {
	decodeDirectoryQuery := func(w http.ResponseWriter, r *http.Request) (identitysdk.DirectoryQuery, bool) {
		var request identitysdk.DirectoryQuery
		if !support.decodeJSON(w, r, &request) {
			return identitysdk.DirectoryQuery{}, false
		}
		return request, true
	}
	registrar.HandleFunc("POST /identity/runtime/directory/user", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.UserLookup
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		user, found, err := binding.Directory().FindUser(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, struct {
			User  identitysdk.User `json:"user"`
			Found bool             `json:"found"`
		}{User: user, Found: found})
	})
	registrar.HandleFunc("POST /identity/runtime/directory/department", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.DepartmentLookup
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		department, found, err := binding.Directory().FindDepartment(r.Context(), request)
		if err != nil {
			support.writeServiceError(w, r, err)
			return
		}
		support.writeJSON(w, http.StatusOK, struct {
			Department identitysdk.Department `json:"department"`
			Found      bool                   `json:"found"`
		}{Department: department, Found: found})
	})
	registrar.HandleFunc("POST /identity/runtime/directory/users", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeDirectoryQuery(w, r)
		if !ok {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Directory().ListUsers(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/runtime/directory/roles", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeDirectoryQuery(w, r)
		if !ok {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Directory().ListRoles(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/runtime/directory/role-assignments", func(w http.ResponseWriter, r *http.Request) {
		var request identitysdk.UserRoleAssignmentQuery
		if !support.decodeJSON(w, r, &request) {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Directory().ListUserRoleAssignments(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/runtime/directory/workforce", func(w http.ResponseWriter, r *http.Request) {
		request, ok := decodeDirectoryQuery(w, r)
		if !ok {
			return
		}
		if !authorizeApplicationCredential(w, r, support, credentials, request.Application) {
			return
		}
		values, err := binding.Directory().ListWorkforce(r.Context(), request)
		writeRuntimeProjection(w, r, values, err, support)
	})
	registrar.HandleFunc("POST /identity/runtime/principal/resolve", func(w http.ResponseWriter, r *http.Request) {
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
