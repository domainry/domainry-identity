package scimpersistence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	scimmodel "github.com/domainry/domainry-identity/internal/domain/scim/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSCIMStoreScopesResourcesAndMaintainsGroupVersions(t *testing.T) {
	databaseStore, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "scim.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Close() })
	if err := databaseStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(identityStore)

	for _, workspaceID := range []string{"workspace-a", "workspace-b"} {
		for _, userID := range []string{"user-1", "user-2"} {
			if err := store.CreateUserLink(t.Context(), scimmodel.UserLink{WorkspaceID: workspaceID, UserID: userID, UserName: userID + "@example.com", ExternalID: workspaceID + "-" + userID}); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.CreateGroup(t.Context(), scimmodel.DirectoryGroup{WorkspaceID: workspaceID, GroupID: "group-1", ExternalID: workspaceID + "-group", DisplayName: "Engineering", MemberIDs: []string{"user-1", "user-2"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateUserLink(t.Context(), scimmodel.UserLink{WorkspaceID: "workspace-a", UserID: "user-3", UserName: "USER-2@EXAMPLE.COM"}); err == nil {
		t.Fatal("case-insensitive SCIM userName uniqueness was not enforced")
	}
	if err := store.CreateGroup(t.Context(), scimmodel.DirectoryGroup{WorkspaceID: "workspace-a", GroupID: "group-2", ExternalID: "workspace-a-group", DisplayName: "Engineering"}); err != nil {
		t.Fatalf("non-unique Group displayName/externalId should be accepted: %v", err)
	}

	group, found, err := store.GetGroup(t.Context(), "workspace-a", "group-1")
	if err != nil || !found || group.Version != 1 || len(group.MemberIDs) != 2 {
		t.Fatalf("initial group=%+v found=%v err=%v", group, found, err)
	}
	deleted, err := store.DeleteUserLink(t.Context(), "workspace-a", "user-1", 1)
	if err != nil || !deleted {
		t.Fatalf("delete user link deleted=%v err=%v", deleted, err)
	}
	group, found, err = store.GetGroup(t.Context(), "workspace-a", "group-1")
	if err != nil || !found || group.Version != 2 || len(group.MemberIDs) != 1 || group.MemberIDs[0] != "user-2" {
		t.Fatalf("updated group=%+v found=%v err=%v", group, found, err)
	}
	other, found, err := store.GetGroup(t.Context(), "workspace-b", "group-1")
	if err != nil || !found || other.Version != 1 || len(other.MemberIDs) != 2 {
		t.Fatalf("other workspace group=%+v found=%v err=%v", other, found, err)
	}
}

func TestSCIMStoreJoinsIdentityTransactionRollback(t *testing.T) {
	databaseStore, err := database.OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "scim-transaction.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseStore.Close() })
	if err := databaseStore.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identityStore, err := identitypersistence.NewSQLIdentityStore(t.Context(), databaseStore.DB(), databaseStore.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(identityStore)
	injected := errors.New("rollback")
	err = identityStore.WithinIdentityTransaction(t.Context(), func(transactionContext context.Context) error {
		if err := store.CreateUserLink(transactionContext, scimmodel.UserLink{WorkspaceID: "workspace-a", UserID: "user-1", UserName: "user@example.com"}); err != nil {
			return err
		}
		if err := store.CreateGroup(transactionContext, scimmodel.DirectoryGroup{WorkspaceID: "workspace-a", GroupID: "group-1", DisplayName: "Engineering", MemberIDs: []string{"user-1"}}); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("transaction error=%v", err)
	}
	if _, found, err := store.GetUserLink(t.Context(), "workspace-a", "user-1"); err != nil || found {
		t.Fatalf("rolled-back user found=%v err=%v", found, err)
	}
	if _, found, err := store.GetGroup(t.Context(), "workspace-a", "group-1"); err != nil || found {
		t.Fatalf("rolled-back group found=%v err=%v", found, err)
	}
}
