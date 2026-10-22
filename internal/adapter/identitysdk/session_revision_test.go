package identitysdkadapter

import (
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityprincipal "github.com/domainry/domainry-identity-sdk/authorization/principal"
	authapplication "github.com/domainry/domainry-identity/internal/application/auth"
	authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
	"golang.org/x/crypto/bcrypt"
)

func TestCurrentSessionInvalidatesCachedAuthorizationBeforeTTL(t *testing.T) {
	for _, change := range []string{"department", "assignment", "role-disabled", "permission-disabled", "user-disabled", "read-error"} {
		t.Run(change, func(t *testing.T) {
			f := newPrincipalReadFixture(t)
			ctx := requestcontext.WithWorkspaceID(f.ctx, "workspace-primary")
			for _, id := range []string{"department-a", "department-b"} {
				if err := f.repo.UpsertIdentityOrganizationUnit(ctx, "workspace-primary", identitymodel.IdentityOrganizationUnit{OrganizationUnitID: id, Code: id, Name: id, NodeType: identitymodel.IdentityOrganizationUnitDepartment, Status: identitymodel.IdentityStatusActive}); err != nil {
					t.Fatal(err)
				}
			}
			passwordHash, err := bcrypt.GenerateFromPassword([]byte("SessionTest1!"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			authStore := authpersistence.NewAuthStore(f.repo.SQLIdentityStore)
			for _, id := range []string{"subject", "observer"} {
				if err := f.repo.UpsertIdentityUser(ctx, "workspace-primary", identitymodel.IdentityUser{UserID: id, Name: id, Email: id + "@example.test", OrgID: "department-a", Status: identitymodel.IdentityStatusActive}); err != nil {
					t.Fatal(err)
				}
				if err := authStore.UpsertIdentityCredential(ctx, "workspace-primary", identitymodel.IdentityCredential{UserID: id, PasswordHash: string(passwordHash)}); err != nil {
					t.Fatal(err)
				}
			}
			auth := authapplication.NewAuthApplicationService(f.identity, authStore, "session-revision-test-secret", "", time.Hour, 24*time.Hour, 5, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
			if err := auth.ConfigureTokenMetadata("https://identity.example.test", "principal-test"); err != nil {
				t.Fatal(err)
			}
			binding := f.resolver.binding
			binding.auth = auth
			binding.descriptor = identitysdk.Descriptor{Issuer: "https://identity.example.test", Audience: "principal-test"}
			cache := identityprincipal.NewMemoryCache()
			resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Cache: cache})
			if err != nil {
				t.Fatal(err)
			}
			login, err := auth.LoginForApplication(ctx, "workspace-primary", "subject@example.test", "SessionTest1!", "principal-test")
			if err != nil {
				t.Fatal(err)
			}
			observer, err := auth.LoginForApplication(ctx, "workspace-primary", "observer@example.test", "SessionTest1!", "principal-test")
			if err != nil {
				t.Fatal(err)
			}
			before, err := resolver.Authenticate(ctx, login.AccessToken)
			if err != nil || before.OrgID != "department-a" {
				t.Fatalf("initial authorization: org=%s err=%v", before.OrgID, err)
			}
			if _, err := resolver.Authenticate(ctx, observer.AccessToken); err != nil {
				t.Fatal(err)
			}
			verified, err := binding.Tokens().Verify(ctx, identitysdk.VerifyTokenRequest{AccessToken: login.AccessToken})
			if err != nil {
				t.Fatal(err)
			}
			current, err := binding.Authentication().CurrentSession(ctx, identitysdk.CurrentSessionRequest{AccessToken: login.AccessToken})
			if err != nil {
				t.Fatal(err)
			}
			key := identityprincipal.CacheKey{WorkspaceID: verified.WorkspaceID, SubjectID: verified.SubjectID, AuthorizationRevision: verified.AuthorizationRevision, ScopeRevision: current.ScopeRevision, TokenID: verified.TokenID}
			entry, found, err := cache.Get(ctx, key, time.Now())
			if err != nil || !found || time.Until(entry.ExpiresAt) < time.Minute {
				t.Fatalf("normal five-minute cache was not primed: found=%v err=%v", found, err)
			}
			if _, err := resolver.Authenticate(ctx, login.AccessToken); err != nil {
				t.Fatalf("unchanged cached session rejected: %v", err)
			}

			switch change {
			case "department":
				user, _, err := f.repo.GetIdentityUser(ctx, "workspace-primary", "subject")
				if err != nil {
					t.Fatal(err)
				}
				user.OrgID = "department-b"
				err = f.repo.UpsertIdentityUser(ctx, "workspace-primary", user)
				if err != nil {
					t.Fatal(err)
				}
			case "assignment":
				err = f.repo.RemoveIdentityUserRole(ctx, "workspace-primary", "subject", "writer-id")
			case "role-disabled":
				err = f.repo.UpsertIdentityRole(ctx, "workspace-primary", identitymodel.IdentityRole{RoleID: "writer-id", Key: "writer", Status: identitymodel.IdentityStatusDisabled})
			case "permission-disabled":
				f.grants[1].Enabled = false
				f.identity.ReplacePermissionDefinitions(f.grants)
			case "user-disabled":
				err = f.repo.SetIdentityUserStatus(ctx, "workspace-primary", "subject", identitymodel.IdentityStatusDisabled)
			case "read-error":
				// Arm the repository's next principal read, not the user query
				// projection (which uses its own persistence read boundary).
				f.repo.users, f.repo.fail = 1, "users"
			}
			if err != nil {
				t.Fatal(err)
			}
			// The signature is still valid. Current authoritative state, not
			// token expiry or an artificially short cache TTL, must revoke access.
			if _, err := binding.Tokens().Verify(ctx, identitysdk.VerifyTokenRequest{AccessToken: login.AccessToken}); err != nil {
				t.Fatalf("old signed token unexpectedly invalid: %v", err)
			}
			_, err = resolver.Authenticate(ctx, login.AccessToken)
			if err == nil {
				t.Fatal("old authorization reused while the ordinary cache was still valid")
			}
			if change == "read-error" && !errors.Is(err, f.repo.err) {
				t.Fatalf("authoritative repository error was not propagated: %v", err)
			}
			if change != "user-disabled" && change != "read-error" {
				var coded *identitysdk.Error
				if !errors.As(err, &coded) || coded.Code != "identity.authorization_revision_stale" {
					t.Fatalf("expected stale authorization revision, got %v", err)
				}
			}
			if _, found, err := cache.Get(ctx, key, time.Now()); err != nil || found {
				t.Fatalf("stale authorization remains cached: found=%v err=%v", found, err)
			}
			if change == "department" || change == "assignment" || change == "user-disabled" {
				if _, err := resolver.Authenticate(ctx, observer.AccessToken); err != nil {
					t.Fatalf("unrelated user's session was invalidated: %v", err)
				}
			}
			if change == "user-disabled" || change == "read-error" {
				return
			}
			refreshed, err := auth.RefreshForApplication(ctx, "workspace-primary", login.RefreshToken, "principal-test")
			if err != nil {
				t.Fatal(err)
			}
			after, err := resolver.Authenticate(ctx, refreshed.AccessToken)
			if err != nil || after.AuthorizationRevision == before.AuthorizationRevision {
				t.Fatalf("refresh did not resolve current authorization: err=%v", err)
			}
			if change == "department" && after.OrgID != "department-b" {
				t.Fatalf("refresh retained old department: %s", after.OrgID)
			}
		})
	}
}

func TestDepartmentTreeChangesRefreshScopeWithoutRevokingUserSession(t *testing.T) {
	f := newPrincipalReadFixture(t)
	ctx := requestcontext.WithWorkspaceID(f.ctx, "workspace-primary")
	for _, id := range []string{"department-a", "department-b"} {
		if err := f.repo.UpsertIdentityOrganizationUnit(ctx, "workspace-primary", identitymodel.IdentityOrganizationUnit{OrganizationUnitID: id, Code: id, Name: id, NodeType: identitymodel.IdentityOrganizationUnitDepartment, Status: identitymodel.IdentityStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.repo.UpsertIdentityUser(ctx, "workspace-primary", identitymodel.IdentityUser{UserID: "subject", Name: "subject", Email: "subject@example.test", OrgID: "department-a", Status: identitymodel.IdentityStatusActive}); err != nil {
		t.Fatal(err)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("SessionTest1!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	authStore := authpersistence.NewAuthStore(f.repo.SQLIdentityStore)
	if err := authStore.UpsertIdentityCredential(ctx, "workspace-primary", identitymodel.IdentityCredential{UserID: "subject", PasswordHash: string(passwordHash)}); err != nil {
		t.Fatal(err)
	}
	auth := authapplication.NewAuthApplicationService(f.identity, authStore, "session-revision-test-secret", "", time.Hour, 24*time.Hour, 5, time.Minute, time.Minute, 3, authpolicy.AuthPasswordPolicy{})
	if err := auth.ConfigureTokenMetadata("https://identity.example.test", "principal-test"); err != nil {
		t.Fatal(err)
	}
	binding := f.resolver.binding
	binding.auth = auth
	binding.descriptor = identitysdk.Descriptor{Issuer: "https://identity.example.test", Audience: "principal-test"}
	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Cache: identityprincipal.NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	login, err := auth.LoginForApplication(ctx, "workspace-primary", "subject@example.test", "SessionTest1!", "principal-test")
	if err != nil {
		t.Fatal(err)
	}
	before, err := resolver.Authenticate(ctx, login.AccessToken)
	if err != nil || len(before.OrgScopeIDs) != 1 {
		t.Fatalf("initial scope=%v err=%v", before.OrgScopeIDs, err)
	}
	parent := "department-a"
	child := identitymodel.IdentityOrganizationUnit{OrganizationUnitID: "department-child", Code: "child", Name: "Child", NodeType: identitymodel.IdentityOrganizationUnitDepartment, ParentID: &parent, Status: identitymodel.IdentityStatusActive}
	if err := f.repo.UpsertIdentityOrganizationUnit(ctx, "workspace-primary", child); err != nil {
		t.Fatal(err)
	}
	afterCreate, err := resolver.Authenticate(ctx, login.AccessToken)
	if err != nil || afterCreate.AuthorizationRevision != before.AuthorizationRevision || len(afterCreate.OrgScopeIDs) != 2 {
		t.Fatalf("new child revoked token or reused old scope: revision=%s scope=%v err=%v", afterCreate.AuthorizationRevision, afterCreate.OrgScopeIDs, err)
	}
	parent = "department-b"
	child.ParentID = &parent
	if err := f.repo.UpsertIdentityOrganizationUnit(ctx, "workspace-primary", child); err != nil {
		t.Fatal(err)
	}
	afterMove, err := resolver.Authenticate(ctx, login.AccessToken)
	if err != nil || afterMove.AuthorizationRevision != before.AuthorizationRevision || len(afterMove.OrgScopeIDs) != 1 || afterMove.OrgScopeIDs[0] != "department-a" {
		t.Fatalf("moved child retained cached access or revoked token: revision=%s scope=%v err=%v", afterMove.AuthorizationRevision, afterMove.OrgScopeIDs, err)
	}
	user, found, err := f.repo.GetIdentityUser(ctx, "workspace-primary", "subject")
	if err != nil || !found {
		t.Fatalf("subject lookup found=%v err=%v", found, err)
	}
	user.Name = "Updated display name"
	if err := f.repo.UpsertIdentityUser(ctx, "workspace-primary", user); err != nil {
		t.Fatal(err)
	}
	afterProfileEdit, err := resolver.Authenticate(ctx, login.AccessToken)
	if err != nil || afterProfileEdit.AuthorizationRevision != before.AuthorizationRevision {
		t.Fatalf("display-name edit revoked an unchanged permission grant: revision=%s err=%v", afterProfileEdit.AuthorizationRevision, err)
	}
}
