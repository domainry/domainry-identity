package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityDirectAuthoringPrimitiveEdges(t *testing.T) {
	if hash, err := identityAuthoringResourceHash("identity.role", "missing", nil, false); err != nil || hash != "empty" {
		t.Fatalf("missing hash=%q err=%v", hash, err)
	}
	if _, err := identityAuthoringResourceHash("identity.role", "invalid", func() {}, true); err == nil {
		t.Fatal("expected unsupported payload fingerprint failure")
	}

	handler, response := newIdentityHTTPHandler(&identityHTTPRepository{})
	handler.writeIdentityAuthoringResource(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "identity.role", "invalid", func() {})
	if response.status != http.StatusInternalServerError || response.err == nil {
		t.Fatalf("write invalid status=%d err=%v", response.status, response.err)
	}

	expectedErr := errors.New("execute failed")
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "failure", err: expectedErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{"identity.roles.write"}}}
			result, err := handler.executeIdentityAuthoringUpsert(
				context.Background(), "identity.role", "role-1", "identity.roles.write", "", "", "", nil,
				principal,
				func(context.Context) (any, bool, error) {
					t.Fatal("current callback should not run without operations")
					return nil, false, nil
				},
				func(context.Context) (any, error) { return "value", test.err },
			)
			if !errors.Is(err, test.err) || result.Value != "value" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestIdentityAuthoringAllowedRequiresScopeAndPermission(t *testing.T) {
	permission := "identity.roles.write"
	for _, test := range []struct {
		name      string
		principal identitymodel.Principal
		wantErr   bool
	}{
		{name: "unknown", principal: identitymodel.Principal{WorkspaceID: "workspace-1"}, wantErr: true},
		{name: "missing workspace", principal: identitymodel.Principal{Known: true}, wantErr: true},
		{name: "missing permission", principal: identitymodel.Principal{Known: true, WorkspaceID: "workspace-1"}, wantErr: true},
		{name: "allowed", principal: identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", Role: identitymodel.RoleSchema{Permissions: []string{permission}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := identityAuthoringAllowed(test.principal, permission)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestIdentityDirectAuthoringCurrentStateEdges(t *testing.T) {
	for _, test := range []struct {
		name    string
		current identityAuthoringCurrent
	}{
		{name: "load failure", current: func(context.Context) (any, bool, error) { return nil, false, errors.New("load failed") }},
		{name: "absent nil value", current: func(context.Context) (any, bool, error) { return nil, false, nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, _ := newIdentityHTTPHandler(&identityHTTPRepository{})
			principal := identitymodel.Principal{Known: true, WorkspaceID: "workspace-1", UserID: "builder", Role: identitymodel.RoleSchema{Permissions: []string{"identity.roles.write"}}}
			_, err := handler.executeIdentityAuthoringUpsert(
				context.Background(), "identity.role", "role-1", "identity.roles.write", "task-1", "key-"+test.name, "empty", map[string]any{"id": "role-1"},
				principal, test.current, func(context.Context) (any, error) { return "unexpected", nil },
			)
			if err == nil {
				t.Fatal("expected current state failure")
			}
		})
	}
}
