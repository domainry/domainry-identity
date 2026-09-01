package remotesdk

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/modulecapability"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// RegisterCapabilityRoutes exposes the shared topology-neutral capability
// wire contract. It authenticates the same application-scoped service
// credential used by Identity's other Remote SDK calls; product disclosure is
// never made public merely because it contains no live grants or credentials.
func RegisterCapabilityRoutes(mux *http.ServeMux, binding identitysdk.Binding, credentials *ApplicationCredentialRegistry) error {
	if mux == nil || binding == nil {
		return fmt.Errorf("Identity capability routes require a mux and Binding")
	}
	handler, err := modulecapability.NewHTTPHandler(binding, func(request *http.Request) error {
		workspaceID := strings.TrimSpace(request.Header.Get("X-Domainry-Workspace-ID"))
		if workspaceID == "" {
			workspaceID = strings.TrimSpace(request.Header.Get("X-Workspace-ID"))
		}
		scope := identitysdk.ApplicationScope{
			TenantID:       identitysdk.TenantID(strings.TrimSpace(request.Header.Get("X-Domainry-Tenant-ID"))),
			WorkspaceID:    identitysdk.WorkspaceID(workspaceID),
			ApplicationKey: identitysdk.ApplicationKey(strings.TrimSpace(request.Header.Get("X-Domainry-Application-Key"))),
		}
		if credentials == nil {
			return &modulecapability.Error{StatusCode: http.StatusUnauthorized, Code: "module_capability.service_credential_required"}
		}
		decision := credentials.Authorize(request.Header.Get("Authorization"), scope)
		if !decision.Authenticated {
			return &modulecapability.Error{StatusCode: http.StatusUnauthorized, Code: "module_capability.service_credential_required"}
		}
		if decision.RateLimited {
			return &modulecapability.Error{StatusCode: http.StatusTooManyRequests, Code: "module_capability.rate_limited", Retryable: true}
		}
		return nil
	})
	if err != nil {
		return err
	}
	mux.Handle(modulecapability.HTTPPrefix+"/", handler)
	return nil
}
