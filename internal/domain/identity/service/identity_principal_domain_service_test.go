// Principal domain service tests.
package service

import (
	"reflect"
	"testing"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPrincipalDomainServiceUsesRolesAndDefaultResolver(t *testing.T) {
	service := NewIdentityPrincipalDomainService(func() []identitymodel.RoleSchema {
		return []identitymodel.RoleSchema{{Key: "member", Permissions: []string{"customer.read"}}}
	}, func() string { return "member" })
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	principal := service.Resolve(ctx, "user-1", "", "")
	if !principal.Known || principal.UserID != "user-1" || principal.Role.Key != "member" {
		t.Fatalf("principal=%#v", principal)
	}
	if !reflect.DeepEqual(principal.Role.Permissions, []string{"customer.read"}) {
		t.Fatalf("permissions=%v", principal.Role.Permissions)
	}
	if unknown := service.Resolve(ctx, "user-1", "missing", ""); unknown.Known {
		t.Fatalf("unknown=%#v", unknown)
	}
}

func TestIdentityPrincipalDomainServiceFallbackAndAlternateRole(t *testing.T) {
	ctx := requestcontext.WithWorkspaceID(t.Context(), "workspace-primary")
	fallback := NewIdentityPrincipalDomainService(nil, nil).Resolve(ctx, "", "", "")
	if !fallback.Known || fallback.UserID != "admin" || fallback.Role.Key != "developer" {
		t.Fatalf("fallback=%#v", fallback)
	}
	service := NewIdentityPrincipalDomainService(func() []identitymodel.RoleSchema {
		return []identitymodel.RoleSchema{{Key: "alternate"}}
	}, nil)
	principal := service.Resolve(ctx, "user", "", " alternate ")
	if !principal.Known || principal.Role.Key != "alternate" {
		t.Fatalf("alternate=%#v", principal)
	}
}
