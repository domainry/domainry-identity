package identity

import (
	"context"
	"net/http"
	"testing"

	auditapplication "github.com/domainry/domainry-identity/internal/application/audit"
	auditmodel "github.com/domainry/domainry-identity/internal/domain/audit/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPolicyReadHandlers(t *testing.T) {
	repo := &identityHTTPRepository{
		roles: []identitymodel.IdentityRole{{ID: "role-1", Key: "sales", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repo)
	handler.policies.ReplaceRoleDefinitions([]identitymodel.RoleSchema{{
		Key: "sales", Permissions: []string{"customer.read"},
		DataPermissions:  []identitymodel.DataPermission{{ObjectKey: "customer", Scope: "all_records", Read: true}},
		FieldPermissions: []identitymodel.FieldPermission{{ObjectKey: "customer", FieldKey: "name", Read: true}},
	}})
	for _, test := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "permissions", call: handler.listIdentityRolePermissions},
		{name: "data scopes", call: handler.listIdentityRoleDataScopes},
		{name: "field permissions", call: handler.listIdentityRoleFieldPermissions},
	} {
		t.Run(test.name, func(t *testing.T) {
			response.status, response.value, response.err = 0, nil, nil
			writer, request := identityRoleRequest(http.MethodGet, "/identity/roles/role-1/policy", "", map[string]string{"roleID": " role-1 "})
			test.call(writer, request)
			if response.status != http.StatusOK || response.value == nil || response.err != nil {
				t.Fatalf("status=%d value=%#v err=%v", response.status, response.value, response.err)
			}
		})
	}

	for _, test := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "permissions", call: handler.listIdentityRolePermissions},
		{name: "data scopes", call: handler.listIdentityRoleDataScopes},
		{name: "field permissions", call: handler.listIdentityRoleFieldPermissions},
	} {
		t.Run(test.name+" error", func(t *testing.T) {
			repo.err = errIdentityHTTPTest
			response.status, response.value, response.err = 0, nil, nil
			writer, request := identityRoleRequest(http.MethodGet, "/identity/roles/role-1/policy", "", map[string]string{"roleID": "role-1"})
			test.call(writer, request)
			if response.err != errIdentityHTTPTest {
				t.Fatalf("service error=%v", response.err)
			}
			repo.err = nil
		})
	}
}

func TestIdentityPolicyAuditHelpersCopyMetadata(t *testing.T) {
	if cloneStringAnyMap(nil) != nil {
		t.Fatal("nil metadata should stay nil")
	}
	source := map[string]any{"count": 1}
	clone := cloneStringAnyMap(source)
	clone["count"] = 2
	if source["count"] != 1 {
		t.Fatalf("source metadata mutated: %#v", source)
	}

	handler, _ := newIdentityHTTPHandler(&identityHTTPRepository{})
	_, request := identityRoleRequest(http.MethodPut, "/identity/roles/role-1/permissions", "", nil)
	handler.appendIdentityMutationAudit(request, "event", "role", "role-1", "summary", nil)
	audit := &identityPolicyAuditRepository{}
	handler.audit = auditapplication.NewAuditApplicationService(audit)
	handler.appendIdentityMutationAudit(request, "event", "role", "role-1", "summary", nil)
	if len(audit.events) != 1 || audit.events[0].Metadata["path"] != request.URL.Path {
		t.Fatalf("nil metadata audit=%#v", audit.events)
	}
}

type identityPolicyAuditRepository struct {
	events []auditmodel.AuditEvent
}

func (r *identityPolicyAuditRepository) InsertAuditEvent(_ context.Context, _ string, event auditmodel.AuditEvent) error {
	r.events = append(r.events, event)
	return nil
}

func (*identityPolicyAuditRepository) ListAuditEvents(context.Context, string, auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	return nil, nil
}

func (*identityPolicyAuditRepository) ListAuditEventsForSystem(context.Context, identitymodel.SystemScope, auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	return nil, nil
}

func (*identityPolicyAuditRepository) ListAuditOptions(context.Context, string, auditmodel.AuditOptionQuery) ([]auditmodel.AuditOption, error) {
	return nil, nil
}
