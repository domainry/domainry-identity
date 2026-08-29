package identity_test

import (
	"context"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

type identityRoleFixtureStore interface {
	UpsertIdentityRole(context.Context, string, identitymodel.IdentityRole) error
}

func seedIdentityDirectoryRole(t *testing.T, store identityRoleFixtureStore, workspace string, role identitymodel.IdentityRole) {
	t.Helper()
	if err := store.UpsertIdentityRole(t.Context(), workspace, role); err != nil {
		t.Fatalf("seed identity directory role %s: %v", role.ID, err)
	}
}
