package identitymodel

import "testing"

func TestSystemPrincipalRequiresExplicitKindAndPurpose(t *testing.T) {
	valid := NewSystemPrincipal(" runtime-provision ", NewSystemScope(SystemScopeInstallation, " manifest install "), RoleSchema{Key: "system"})
	if !valid.Known || valid.UserID != "runtime-provision" || valid.SystemScope.Purpose != "manifest install" {
		t.Fatalf("unexpected explicit system principal: %#v", valid)
	}
	for _, scope := range []SystemScope{
		NewSystemScope("unknown", "purpose"),
		NewSystemScope(SystemScopeBootstrap, ""),
	} {
		if principal := NewSystemPrincipal("system", scope, RoleSchema{}); principal.Known || principal.SystemScope.Valid() {
			t.Fatalf("invalid system scope produced authenticated principal: %#v", principal)
		}
	}
}
