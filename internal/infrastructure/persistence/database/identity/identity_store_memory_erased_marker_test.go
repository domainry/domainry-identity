package identity

import (
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"testing"
)

func TestMemoryIdentityErasedMarkerCannotBeRestoredOrRemovedByManagement(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := t.Context()
	if err := store.UpsertIdentityUsersAtomically(ctx, "workspace-a", []identitymodel.IdentityUser{{ID: "erased-user", Status: "erased"}, {ID: "peer", Name: "Original"}}); err != nil {
		t.Fatal(err)
	}
	marker, _, _ := store.GetIdentityUser(ctx, "workspace-a", "erased-user")
	replacement := identitymodel.IdentityUser{ID: "erased-user", Name: "Private restored", Email: "private@example.test", Status: identitymodel.IdentityStatusActive}
	scope := identitymodel.IdentityDataScopeFilter{Unrestricted: true}
	_ = store.UpsertIdentityUser(ctx, "workspace-a", replacement)
	_ = store.UpsertIdentityUserWithRoleAssignmentsAtomically(ctx, "workspace-a", replacement, nil)
	_, _ = store.UpsertIdentityUserWithRoleAssignmentsWithinDataScopeAtomically(ctx, "workspace-a", replacement, nil, scope)
	_, _, _ = store.UpdateIdentityUserLocale(ctx, "workspace-a", "erased-user", "en-US", marker.Version)
	_, _ = store.SetIdentityUserStatusWithinDataScope(ctx, "workspace-a", "erased-user", identitymodel.IdentityStatusDisabled, scope)
	_, _ = store.RemoveIdentityUserWithinDataScope(ctx, "workspace-a", "erased-user", scope)
	batch := []identitymodel.IdentityUser{{ID: "peer", Name: "Changed"}, replacement}
	if err := store.UpsertIdentityUsersAtomically(ctx, "workspace-a", batch); err == nil {
		t.Fatal("bulk restored erased marker")
	}
	if changed, err := store.UpdateIdentityUsersWithinDataScopeAtomically(ctx, "workspace-a", batch, scope); err != nil || changed {
		t.Fatalf("bulk changed=%t err=%v", changed, err)
	}
	after, found, err := store.GetIdentityUser(ctx, "workspace-a", "erased-user")
	if err != nil || !found || after != marker {
		t.Fatalf("marker=%+v found=%t err=%v", after, found, err)
	}
	peer, _, _ := store.GetIdentityUser(ctx, "workspace-a", "peer")
	if peer.Name != "Original" || peer.Version != 1 {
		t.Fatalf("bulk failed after mutating peer: %+v", peer)
	}
}
