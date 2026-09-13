package remotesdk

import (
	"encoding/json"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	"net/http"
)

func registerSubjectLifecycleRoutes(registrar RouteRegistrar, binding identitysdk.Binding, support Support, credentials *ApplicationCredentialRegistry) {
	for _, operation := range []string{"preview", "export", "erase"} {
		registrar.HandleFunc("POST /identity/system/subjects/"+operation, func(w http.ResponseWriter, r *http.Request) {
			var request identitysdk.SubjectErasureRequest
			if !support.decodeJSON(w, r, &request) {
				return
			}
			scope := runtimeApplicationScope(r)
			if !authorizeApplicationCredential(w, r, support, credentials, scope) {
				return
			}
			if request.WorkspaceID != string(scope.WorkspaceID) {
				support.writeServiceError(w, r, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.workspace_mismatch"})
				return
			}
			subjects, ok := binding.(identitysdk.SystemSubjectBinding)
			if !ok || subjects.SystemSubjects() == nil {
				support.writeServiceError(w, r, &identitysdk.Error{StatusCode: http.StatusNotImplemented, Code: "identity.subject_lifecycle_unavailable"})
				return
			}
			ctx := runtimeApplicationContext(r, scope)
			var output json.RawMessage
			var err error
			switch operation {
			case "preview":
				output, err = subjects.SystemSubjects().PreviewSubject(ctx, request.WorkspaceID, request.SubjectID)
			case "export":
				output, err = subjects.SystemSubjects().ExportSubject(ctx, request.WorkspaceID, request.SubjectID)
			case "erase":
				output, err = subjects.SystemSubjects().EraseSubjectForRequest(ctx, request)
			}
			if err != nil {
				support.writeServiceError(w, r, err)
				return
			}
			support.writeJSON(w, http.StatusOK, output)
		})
	}
}
