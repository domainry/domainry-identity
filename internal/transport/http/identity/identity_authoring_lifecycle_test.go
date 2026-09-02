package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditmodel "github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/requestcontext"
	auditapplication "github.com/domainry/domainry-identity/internal/application/auditbinding"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityAuthoringAuditRepository struct {
	events []auditmodel.AuditEvent
	err    error
}

func (r *identityAuthoringAuditRepository) InsertAuditEvent(_ context.Context, _ string, event auditmodel.AuditEvent) error {
	r.events = append(r.events, event)
	return nil
}

func (r *identityAuthoringAuditRepository) ListAuditEvents(_ context.Context, workspaceID string, query auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	if r.err != nil {
		return nil, r.err
	}
	items := make([]auditmodel.AuditEvent, 0, len(r.events))
	for _, event := range r.events {
		if event.WorkspaceID == workspaceID && event.ObjectKey == query.ObjectKey && event.RecordID == query.RecordID {
			items = append(items, event)
		}
	}
	return items, nil
}

func TestIdentityAuthoringLifecycleCoversLookupMissesAndFailures(t *testing.T) {
	for _, test := range []struct {
		name    string
		pathKey string
		call    func(*IdentityHandler, http.ResponseWriter, *http.Request)
	}{
		{name: "organizationUnit", pathKey: "organizationUnitID", call: func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			handler.getIdentityOrganizationUnit(w, r)
		}},
		{name: "role", pathKey: "roleID", call: func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) { handler.getIdentityRole(w, r) }},
		{name: "menu", pathKey: "menuID", call: func(handler *IdentityHandler, w http.ResponseWriter, r *http.Request) { handler.getIdentityMenu(w, r) }},
	} {
		t.Run(test.name+" miss", func(t *testing.T) {
			repository := &identityHTTPRepository{
				organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "other"}},
				roles:             []identitymodel.IdentityRole{{ID: "other"}},
				menus:             []identitymodel.IdentityMenu{{ID: "other"}},
			}
			handler, response := newIdentityHTTPHandler(repository)
			request := httptest.NewRequest(http.MethodGet, "/identity/missing", nil)
			request = request.WithContext(requestcontext.WithWorkspaceID(request.Context(), "workspace-1"))
			request.SetPathValue(test.pathKey, "missing")
			test.call(handler, httptest.NewRecorder(), request)
			if response.status != http.StatusNotFound {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
		t.Run(test.name+" failure", func(t *testing.T) {
			handler, response := newIdentityHTTPHandler(&identityHTTPRepository{err: errIdentityHTTPTest})
			request := httptest.NewRequest(http.MethodGet, "/identity/failure", nil)
			request = request.WithContext(requestcontext.WithWorkspaceID(request.Context(), "workspace-1"))
			request.SetPathValue(test.pathKey, "missing")
			test.call(handler, httptest.NewRecorder(), request)
			if response.status != http.StatusInternalServerError {
				t.Fatalf("status=%d err=%v", response.status, response.err)
			}
		})
	}

	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.audit = auditapplication.NewAuditApplicationService(&identityAuthoringAuditRepository{err: errors.New("audit unavailable")})
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"audit.governance.read"}}}
	}
	request := httptest.NewRequest(http.MethodGet, "/identity/roles/manager/versions", nil)
	request.SetPathValue("roleID", "manager")
	handler.identityAuthoringVersions("identity.role", "identity_role", "roleID", "identity_role_updated")(httptest.NewRecorder(), request)
	if response.status != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d err=%v", response.status, response.err)
	}
}

func (r *identityAuthoringAuditRepository) ListAuditEventsForSystem(context.Context, identitymodel.SystemScope, auditmodel.AuditEventQuery) ([]auditmodel.AuditEvent, error) {
	return append([]auditmodel.AuditEvent(nil), r.events...), nil
}

func (*identityAuthoringAuditRepository) ListAuditOptions(context.Context, string, auditmodel.AuditOptionQuery) ([]auditmodel.AuditOption, error) {
	return nil, nil
}

func TestIdentityAuthoringLifecycleReadsResourcesAndAuditRevisions(t *testing.T) {
	repository := &identityHTTPRepository{
		organizationUnits: []identitymodel.IdentityOrganizationUnit{{ID: "sales", Name: "Sales"}},
		roles:             []identitymodel.IdentityRole{{ID: "manager", Key: "manager", Label: "Manager", Status: identitymodel.IdentityStatusActive}},
		menus:             []identitymodel.IdentityMenu{{ID: "orders", Key: "orders", Label: "Orders", Status: identitymodel.IdentityStatusActive}},
	}
	handler, response := newIdentityHTTPHandler(repository)

	for _, item := range []struct {
		pathKey string
		id      string
		call    func(http.ResponseWriter, *http.Request)
	}{
		{pathKey: "organizationUnitID", id: "sales", call: handler.getIdentityOrganizationUnit},
		{pathKey: "roleID", id: "manager", call: handler.getIdentityRole},
		{pathKey: "menuID", id: "orders", call: handler.getIdentityMenu},
	} {
		response.status, response.value, response.err = 0, nil, nil
		request := httptest.NewRequest(http.MethodGet, "/identity/resource/"+item.id, nil)
		request = request.WithContext(requestcontext.WithWorkspaceID(request.Context(), "workspace-1"))
		request.SetPathValue(item.pathKey, item.id)
		recorder := httptest.NewRecorder()
		item.call(recorder, request)
		if response.status != http.StatusOK {
			t.Fatalf("get %s status=%d err=%v", item.pathKey, response.status, response.err)
		}
		if resourceHash := recorder.Header().Get(identityResourceHashHeader); resourceHash == "" || resourceHash == "empty" {
			t.Fatalf("get %s resource hash=%q", item.pathKey, resourceHash)
		}
	}

	handler.audit = auditapplication.NewAuditApplicationService(&identityAuthoringAuditRepository{events: []auditmodel.AuditEvent{
		{ID: "revision-1", WorkspaceID: "workspace-1", Event: "identity_role_updated", ObjectKey: "identity_role", RecordID: "manager"},
		{ID: "ignored-event", WorkspaceID: "workspace-1", Event: "identity_role_permissions_updated", ObjectKey: "identity_role", RecordID: "manager"},
		{ID: "ignored-resource", WorkspaceID: "workspace-1", Event: "identity_role_updated", ObjectKey: "identity_role", RecordID: "other"},
	}})
	handler.principal = func(*http.Request) identitymodel.Principal {
		return identitymodel.Principal{Known: true, UserID: "reviewer-1", WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"audit.governance.read"}}}
	}
	request := httptest.NewRequest(http.MethodGet, "/identity/roles/manager/versions", nil)
	request.SetPathValue("roleID", "manager")
	handler.identityAuthoringVersions("identity.role", "identity_role", "roleID", "identity_role_updated")(httptest.NewRecorder(), request)
	value, ok := response.value.(map[string]any)
	if response.status != http.StatusOK || !ok || value["versioning"] != "audit_revision" || value["count"] != 1 {
		t.Fatalf("versions status=%d value=%#v err=%v", response.status, response.value, response.err)
	}

	handler.audit = nil
	handler.identityAuthoringVersions("identity.role", "identity_role", "roleID", "identity_role_updated")(httptest.NewRecorder(), request)
	if response.status != http.StatusFailedDependency {
		t.Fatalf("missing audit status=%d", response.status)
	}
}

func TestIdentityAuthoringLeafValidatorsAcceptCapabilityPayloads(t *testing.T) {
	repository := &identityHTTPRepository{roles: []identitymodel.IdentityRole{{ID: "manager", Key: "manager", Label: "Manager", Status: identitymodel.IdentityStatusActive}}}
	handler, response := newIdentityHTTPHandler(repository)

	tests := []struct {
		pathKey string
		id      string
		body    string
		call    func(http.ResponseWriter, *http.Request)
	}{
		{pathKey: "roleID", id: "manager", body: `{"data_scopes":[{"resource":"customer","scope":"all_records"}]}`, call: handler.validateIdentityRoleDataScopeAuthoring},
		{pathKey: "roleID", id: "manager", body: `{"field_permissions":[{"resource":"customer","field":"name","visible":true,"editable":false}]}`, call: handler.validateIdentityRoleFieldPermissionAuthoring},
		{pathKey: "menuID", id: "orders", body: `{"key":"orders","label":"Orders","status":"active"}`, call: handler.validateIdentityMenuAuthoring},
	}
	for _, item := range tests {
		response.status, response.value, response.err = 0, nil, nil
		request := httptest.NewRequest(http.MethodPost, "/identity/validate", strings.NewReader(item.body))
		request.SetPathValue(item.pathKey, item.id)
		item.call(httptest.NewRecorder(), request)
		if response.status != http.StatusOK {
			t.Fatalf("validate %s status=%d value=%#v err=%v", item.pathKey, response.status, response.value, response.err)
		}
	}
}
