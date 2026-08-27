package service

import (
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestDefaultSessionRoleSelection(t *testing.T) {
	if role := defaultAuthRole(nil); role != "" {
		t.Fatalf("empty roles returned %q", role)
	}
	if role := defaultAuthRole([]identitymodel.IdentityRole{{ID: "role-admin", Key: "admin"}}); role != "admin" {
		t.Fatalf("preferred role key returned %q", role)
	}
	if role := defaultAuthRole([]identitymodel.IdentityRole{{ID: "admin", Key: "custom-admin"}}); role != "custom-admin" {
		t.Fatalf("preferred role id returned %q", role)
	}
	if role := defaultAuthRole([]identitymodel.IdentityRole{
		{ID: "platform", Key: "platform_support"},
		{ID: "reader", Key: "reader"},
		{ID: "workspace", Key: "workspace-owner"},
	}); role != "reader" {
		t.Fatalf("first business role returned %q", role)
	}
	if role := defaultAuthRole([]identitymodel.IdentityRole{
		{ID: "platform", Key: "platform_support"},
		{ID: "reader", Key: "reader"},
	}); role != "reader" {
		t.Fatalf("business fallback role returned %q", role)
	}
	if role := defaultAuthRole([]identitymodel.IdentityRole{
		{ID: "identity", Key: "identity_support"},
		{ID: "pipeline", Key: "pipeline_operator"},
	}); role != "identity_support" {
		t.Fatalf("all-system fallback role returned %q", role)
	}
}

func TestSystemManagementRoleClassification(t *testing.T) {
	for _, roleKey := range []string{" identity_support ", "platform_support", "pipeline_operator"} {
		if !systemManagementRole(roleKey) {
			t.Fatalf("expected %q to be a system management role", roleKey)
		}
	}
	if systemManagementRole("sales") {
		t.Fatal("sales must remain a business role")
	}
}
