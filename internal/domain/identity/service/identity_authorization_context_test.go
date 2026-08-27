package service

import (
	"context"
	"errors"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestIdentityAuthorizationRejectsCancelledContextBeforeRepositoryAccess(t *testing.T) {
	service := NewIdentityDomainService(nil, []identitymodel.IdentityPermissionDefinition{{Key: "workspace.admin"}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := service.ResolvePrincipal(ctx, "admin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolvePrincipal error=%v, want context.Canceled", err)
	}
	if _, err := service.ResolveEffectivePermissions(ctx, "admin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveEffectivePermissions error=%v, want context.Canceled", err)
	}
	if _, err := service.ResolveEffectiveMenus(ctx, "admin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveEffectiveMenus error=%v, want context.Canceled", err)
	}
	if _, _, err := service.FindUser(ctx, "admin"); !errors.Is(err, context.Canceled) {
		t.Fatalf("FindUser error=%v, want context.Canceled", err)
	}
}
