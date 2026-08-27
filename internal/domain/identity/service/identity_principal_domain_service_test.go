// Principal domain service tests.
package service

import (
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityPrincipalDomainServiceUsesRolesAndDefaultResolver(t *testing.T) {
	service := NewIdentityPrincipalDomainService(func() []identitymodel.RoleSchema {
		return []identitymodel.RoleSchema{{Key: "member", Permissions: []string{"customer.read"}}}
	}, func() string { return "member" })
	principal := service.Resolve(t.Context(), "user-1", "", "")
	if !principal.Known || principal.UserID != "user-1" || principal.Role.Key != "member" {
		t.Fatalf("principal=%#v", principal)
	}
	if !reflect.DeepEqual(principal.Role.Permissions, []string{"customer.read"}) {
		t.Fatalf("permissions=%v", principal.Role.Permissions)
	}
	if unknown := service.Resolve(t.Context(), "user-1", "missing", ""); unknown.Known {
		t.Fatalf("unknown=%#v", unknown)
	}
}

func TestIdentityPrincipalDomainServiceFallbackAndAlternateRole(t *testing.T) {
	fallback := NewIdentityPrincipalDomainService(nil, nil).Resolve(t.Context(), "", "", "")
	if !fallback.Known || fallback.UserID != "admin" || fallback.Role.Key != "developer" {
		t.Fatalf("fallback=%#v", fallback)
	}
	service := NewIdentityPrincipalDomainService(func() []identitymodel.RoleSchema {
		return []identitymodel.RoleSchema{{Key: "alternate"}}
	}, nil)
	principal := service.Resolve(t.Context(), "user", "", " alternate ")
	if !principal.Known || principal.Role.Key != "alternate" {
		t.Fatalf("alternate=%#v", principal)
	}
}
