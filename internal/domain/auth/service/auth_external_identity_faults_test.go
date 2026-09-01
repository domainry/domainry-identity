package service

import authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"context"
	"errors"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	"strings"
	"sync"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

func TestExternalLoginPropagatesRepositoryFailures(t *testing.T) {
	fault := errors.New("external identity repository fault")
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject", Email: "subject@example.com"}

	t.Run("external account lookup", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.listAccountsErr = fault
		_, err := auth.ExternalLogin(t.Context(), "workspace-primary", assertion, true)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("linked identity lookup", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		authRepository.accounts = []identitymodel.IdentityExternalAccount{{ID: "external", UserID: "user", Provider: "oidc", ProviderSubject: "subject"}}
		identityRepository.listUsersErr = fault
		_, err := auth.ExternalLogin(t.Context(), "workspace-primary", assertion, true)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("linked identity missing", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.accounts = []identitymodel.IdentityExternalAccount{{ID: "external", UserID: "missing", Provider: "oidc", ProviderSubject: "subject"}}
		if _, err := auth.ExternalLogin(t.Context(), "workspace-primary", assertion, true); err == nil {
			t.Fatal("expected a missing linked identity to be rejected")
		}
	})

	t.Run("verified email lookup", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listUsersErr = fault
		_, err := auth.ExternalLogin(t.Context(), "workspace-primary", assertion, true)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("verified email account link", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("existing", assertion.Email)}
		authRepository.upsertAccountErr = fault
		_, err := auth.ExternalLogin(t.Context(), "workspace-primary", assertion, true)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("new identity account link", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.upsertAccountErr = fault
		_, err := auth.ExternalLogin(t.Context(), "workspace-primary", assertion, true)
		assertExternalAuthFault(t, err, fault)
	})
}

func TestExternalAccountMutationPropagatesRepositoryFailures(t *testing.T) {
	fault := errors.New("external account mutation fault")
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject", Email: "subject@example.com"}

	t.Run("bind identity lookup", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listUsersErr = fault
		_, err := auth.BindExternalAccount(t.Context(), "workspace-primary", "user", assertion)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("bind external account lookup", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", assertion.Email)}
		authRepository.listAccountsErr = fault
		_, err := auth.BindExternalAccount(t.Context(), "workspace-primary", "user", assertion)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("bind external account write", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("user", assertion.Email)}
		authRepository.upsertAccountErr = fault
		_, err := auth.BindExternalAccount(t.Context(), "workspace-primary", "user", assertion)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("unbind account listing", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.listAccountsErr = fault
		err := auth.UnbindExternalAccount(t.Context(), "workspace-primary", "user", "oidc", "external")
		assertExternalAuthFault(t, err, fault)
	})
}

func TestExternalIdentityCreationPropagatesRepositoryFailures(t *testing.T) {
	fault := errors.New("external identity creation fault")
	assertion := authmodel.AuthExternalIdentityAssertion{Provider: "oidc", Subject: "subject", Email: "subject@example.com"}
	policy := authmodel.AuthExternalLoginPolicy{AutoCreateUsers: true, DefaultRoleKey: "sales"}

	t.Run("identity collision lookup", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listUsersErr = fault
		_, err := auth.createExternalIdentityUser(t.Context(), assertion, policy)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("identity write", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.upsertUserErr = fault
		_, err := auth.createExternalIdentityUser(t.Context(), assertion, policy)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("role listing", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listRolesErr = fault
		_, err := auth.createExternalIdentityUser(t.Context(), assertion, policy)
		assertExternalAuthFault(t, err, fault)
	})

	t.Run("role assignment", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.assignRoleErr = fault
		_, err := auth.createExternalIdentityUser(t.Context(), assertion, policy)
		assertExternalAuthFault(t, err, fault)
	})
}

func TestExternalIdentityPrivilegedDefaultRoleIsIgnored(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	role, ok, err := auth.roleForExternalAssertion(t.Context(), authmodel.AuthExternalIdentityAssertion{}, authmodel.AuthExternalLoginPolicy{DefaultRoleKey: "admin"})
	if err != nil {
		t.Fatalf("resolve privileged default role: %v", err)
	}
	if ok || role.ID != "" {
		t.Fatalf("privileged default role must not be automatically assigned: %#v", role)
	}
}

func assertExternalAuthFault(t *testing.T, err error, fault error) {
	t.Helper()
	if !errors.Is(err, fault) {
		t.Fatalf("expected repository fault %v, got %v", fault, err)
	}
}

func activeExternalIdentityUser(id string, email string) identitymodel.IdentityUser {
	return identitymodel.IdentityUser{
		ID: id, Name: id, Email: email, Status: identitymodel.IdentityStatusActive,
	}
}

func newFaultAuthDomainService() (*AuthDomainService, *faultExternalIdentityRepository, *faultExternalAuthRepository) {
	identityRepository := &faultExternalIdentityRepository{
		departments: []identitymodel.IdentityDepartment{
			{ID: "company", Name: "Company", Path: "/company", Status: identitymodel.IdentityStatusActive},
			{ID: "dept_sales", Name: "Sales", Path: "/sales", Status: identitymodel.IdentityStatusActive},
		},
		roles: []identitymodel.IdentityRole{
			{ID: "role-sales", Key: "sales", Label: "Sales", Status: identitymodel.IdentityStatusActive},
			{ID: "role-admin", Key: "admin", Label: "Admin", Status: identitymodel.IdentityStatusActive},
		},
		roleDefinitions: map[string]identitymodel.RoleSchema{
			"sales": {Key: "sales", Name: "Sales", RecordScope: "all_records"},
			"admin": {Key: "admin", Name: "Admin", Permissions: []string{"identity.roles.list"}, RecordScope: "all_records", RiskLevel: identitymodel.IdentityRoleRiskPrivileged},
		},
	}
	authRepository := &faultExternalAuthRepository{}
	return NewAuthDomainService(identityRepository, authRepository, "test-secret", "Password@2026", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{}), identityRepository, authRepository
}

type faultExternalIdentityRepository struct {
	users              []identitymodel.IdentityUser
	departments        []identitymodel.IdentityDepartment
	roles              []identitymodel.IdentityRole
	roleDefinitions    map[string]identitymodel.RoleSchema
	roleAssignments    []identitymodel.IdentityUserRoleAssignment
	listUsersErr       error
	listRolesErr       error
	listAssignmentsErr error
	upsertUserErr      error
	reconcileErr       error
	reconcileCalls     int
	assignRoleErr      error
}

func (r *faultExternalIdentityRepository) ReconcileSystemManagedBusinessRoles(context.Context, string) error {
	r.reconcileCalls++
	return r.reconcileErr
}

func (r *faultExternalIdentityRepository) AssignUserRole(ctx context.Context, assignment identitymodel.IdentityUserRoleAssignment) error {
	return r.AssignIdentityUserRole(ctx, assignment)
}

func (r *faultExternalIdentityRepository) ListRoles(ctx context.Context) ([]identitymodel.IdentityRole, error) {
	return r.ListIdentityRoles(ctx)
}

func (r *faultExternalIdentityRepository) UpsertUser(ctx context.Context, user identitymodel.IdentityUser) error {
	return r.UpsertIdentityUser(ctx, user)
}

func (r *faultExternalIdentityRepository) UserByID(ctx context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	return r.GetIdentityUser(ctx, userID)
}

func (r *faultExternalIdentityRepository) UserByLogin(ctx context.Context, login string) (identitymodel.IdentityUser, bool, error) {
	users, err := r.ListIdentityUsers(ctx)
	if err != nil {
		return identitymodel.IdentityUser{}, false, err
	}
	for _, user := range users {
		if user.ID == login || strings.EqualFold(user.Email, login) || user.Phone == login {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}

func (r *faultExternalIdentityRepository) ActiveRolesForUser(ctx context.Context, userID string) ([]identitymodel.IdentityRole, error) {
	assignments, err := r.ListIdentityUserRoleAssignments(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles, err := r.ListIdentityRoles(ctx)
	if err != nil {
		return nil, err
	}
	result := []identitymodel.IdentityRole{}
	for _, assignment := range assignments {
		for _, role := range roles {
			if role.ID == assignment.RoleID && role.Status != identitymodel.IdentityStatusDisabled {
				result = append(result, role)
			}
		}
	}
	return result, nil
}

func (r *faultExternalIdentityRepository) PublishedRoleDefinition(_ context.Context, key string) (identitymodel.RoleSchema, bool) {
	role, ok := r.roleDefinitions[key]
	return role, ok
}

func (r *faultExternalIdentityRepository) ResolveEffectivePermissions(ctx context.Context, userID string) ([]string, error) {
	roles, err := r.ActiveRolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	permissions := []string{}
	for _, role := range roles {
		if published, ok := r.PublishedRoleDefinition(ctx, role.Key); ok {
			permissions = append(permissions, published.Permissions...)
		}
	}
	return permissions, nil
}

func (r *faultExternalIdentityRepository) ResolvePrincipal(ctx context.Context, userID string) (identitymodel.Principal, error) {
	user, found, err := r.UserByID(ctx, userID)
	if err != nil || !found {
		return identitymodel.Principal{}, err
	}
	roles, err := r.ActiveRolesForUser(ctx, userID)
	if err != nil {
		return identitymodel.Principal{}, err
	}
	principal := identitymodel.Principal{Known: true, UserID: user.ID}
	if len(roles) > 0 {
		principal.Role, _ = r.PublishedRoleDefinition(ctx, roles[0].Key)
	}
	return principal, nil
}

func (r *faultExternalIdentityRepository) ListIdentityUsers(context.Context) ([]identitymodel.IdentityUser, error) {
	if r.listUsersErr != nil {
		return nil, r.listUsersErr
	}
	return append([]identitymodel.IdentityUser(nil), r.users...), nil
}

func (r *faultExternalIdentityRepository) GetIdentityUser(_ context.Context, userID string) (identitymodel.IdentityUser, bool, error) {
	if r.listUsersErr != nil {
		return identitymodel.IdentityUser{}, false, r.listUsersErr
	}
	for _, user := range r.users {
		if user.ID == userID {
			return user, true, nil
		}
	}
	return identitymodel.IdentityUser{}, false, nil
}

func (r *faultExternalIdentityRepository) ListIdentityDepartments(context.Context) ([]identitymodel.IdentityDepartment, error) {
	return append([]identitymodel.IdentityDepartment(nil), r.departments...), nil
}

func (r *faultExternalIdentityRepository) UpsertIdentityUser(_ context.Context, user identitymodel.IdentityUser) error {
	if r.upsertUserErr != nil {
		return r.upsertUserErr
	}
	for index := range r.users {
		if r.users[index].ID == user.ID {
			r.users[index] = user
			return nil
		}
	}
	r.users = append(r.users, user)
	return nil
}

func (r *faultExternalIdentityRepository) UpsertIdentityUsersAtomically(_ context.Context, users []identitymodel.IdentityUser) error {
	if r.upsertUserErr != nil {
		return r.upsertUserErr
	}
	r.users = append([]identitymodel.IdentityUser(nil), users...)
	return nil
}

func (r *faultExternalIdentityRepository) ListIdentityRoles(context.Context) ([]identitymodel.IdentityRole, error) {
	if r.listRolesErr != nil {
		return nil, r.listRolesErr
	}
	return append([]identitymodel.IdentityRole(nil), r.roles...), nil
}

func (r *faultExternalIdentityRepository) AssignIdentityUserRole(_ context.Context, assignment identitymodel.IdentityUserRoleAssignment) error {
	if r.assignRoleErr != nil {
		return r.assignRoleErr
	}
	r.roleAssignments = append(r.roleAssignments, assignment)
	return nil
}

func (r *faultExternalIdentityRepository) ListIdentityUserRoleAssignments(_ context.Context, userID string) ([]identitymodel.IdentityUserRoleAssignment, error) {
	if r.listAssignmentsErr != nil {
		return nil, r.listAssignmentsErr
	}
	assignments := make([]identitymodel.IdentityUserRoleAssignment, 0, len(r.roleAssignments))
	for _, assignment := range r.roleAssignments {
		if userID == "" || assignment.UserID == userID {
			assignments = append(assignments, assignment)
		}
	}
	return assignments, nil
}

type faultExternalAuthRepository struct {
	authrepository.AuthRepository
	accounts              []identitymodel.IdentityExternalAccount
	credentials           map[string]identitymodel.IdentityCredential
	refreshTokens         []identitymodel.AuthRefreshToken
	listAccountsErr       error
	upsertAccountErr      error
	getCredentialErr      error
	upsertCredentialErr   error
	recordLoginSuccessErr error
	recordLoginFailureErr error
	createRefreshTokenErr error
	getRefreshTokenErr    error
	getRefreshTokenErrAt  int
	getRefreshTokenCalls  int
	revokeRefreshTokenErr error
	discardRefreshTokens  bool
	revokedRefreshTokens  []string
	refreshMu             sync.Mutex
}

func (r *faultExternalAuthRepository) AuthSessionState(_ context.Context, _, userID, sessionID string, now time.Time) (string, error) {
	found, revoked := false, false
	for _, token := range r.refreshTokens {
		if token.UserID != userID || token.SessionID != sessionID {
			continue
		}
		found = true
		if token.RevokedAt != "" {
			revoked = true
			continue
		}
		expires, err := time.Parse(time.RFC3339, token.ExpiresAt)
		if err == nil && expires.After(now) {
			return authrepository.AuthSessionStateActive, nil
		}
	}
	if revoked {
		return authrepository.AuthSessionStateRevoked, nil
	}
	if found {
		return authrepository.AuthSessionStateExpired, nil
	}
	return authrepository.AuthSessionStateMissing, nil
}

func (r *faultExternalAuthRepository) RevokeOtherAuthSessions(_ context.Context, _, userID, currentSessionID, revokedAt string) (int, error) {
	return r.revokeLogicalSessions(userID, currentSessionID, true, revokedAt), nil
}

func (r *faultExternalAuthRepository) RevokeAuthSession(_ context.Context, _, userID, sessionID, revokedAt string) (int, error) {
	return r.revokeLogicalSessions(userID, sessionID, false, revokedAt), nil
}

func (r *faultExternalAuthRepository) revokeLogicalSessions(userID, sessionID string, exclude bool, revokedAt string) int {
	changed := map[string]struct{}{}
	for index := range r.refreshTokens {
		token := &r.refreshTokens[index]
		matches := token.SessionID == sessionID
		if token.UserID != userID || token.RevokedAt != "" || matches == exclude {
			continue
		}
		token.RevokedAt, token.LastUsedAt = revokedAt, revokedAt
		changed[token.SessionID] = struct{}{}
		r.revokedRefreshTokens = append(r.revokedRefreshTokens, token.ID)
	}
	return len(changed)
}

func (r *faultExternalAuthRepository) ListIdentityExternalAccounts(_ context.Context, _, userID string) ([]identitymodel.IdentityExternalAccount, error) {
	if r.listAccountsErr != nil {
		return nil, r.listAccountsErr
	}
	accounts := make([]identitymodel.IdentityExternalAccount, 0, len(r.accounts))
	for _, account := range r.accounts {
		if userID == "" || account.UserID == userID {
			accounts = append(accounts, account)
		}
	}
	return accounts, nil
}

func (r *faultExternalAuthRepository) UpsertIdentityExternalAccount(_ context.Context, _ string, account identitymodel.IdentityExternalAccount) error {
	if r.upsertAccountErr != nil {
		return r.upsertAccountErr
	}
	r.accounts = append(r.accounts, account)
	return nil
}

func (r *faultExternalAuthRepository) GetIdentityCredential(_ context.Context, _, userID string) (identitymodel.IdentityCredential, bool, error) {
	if r.getCredentialErr != nil {
		return identitymodel.IdentityCredential{}, false, r.getCredentialErr
	}
	credential, ok := r.credentials[userID]
	return credential, ok, nil
}

func (r *faultExternalAuthRepository) UpsertIdentityCredential(_ context.Context, _ string, credential identitymodel.IdentityCredential) error {
	if r.upsertCredentialErr != nil {
		return r.upsertCredentialErr
	}
	if r.credentials == nil {
		r.credentials = map[string]identitymodel.IdentityCredential{}
	}
	r.credentials[credential.UserID] = credential
	return nil
}

func (r *faultExternalAuthRepository) RecordIdentityLoginSuccess(context.Context, string, string, string) error {
	return r.recordLoginSuccessErr
}

func (r *faultExternalAuthRepository) RecordIdentityLoginFailure(_ context.Context, _ string, userID string, maxFailures int, lockedUntil, _ string) error {
	if r.recordLoginFailureErr != nil {
		return r.recordLoginFailureErr
	}
	credential := r.credentials[userID]
	credential.FailedLoginCount++
	if maxFailures > 0 && credential.FailedLoginCount >= maxFailures {
		credential.LockedUntil = lockedUntil
	}
	r.credentials[userID] = credential
	return nil
}

func (r *faultExternalAuthRepository) CreateAuthRefreshToken(_ context.Context, _ string, token identitymodel.AuthRefreshToken) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.createRefreshTokenErr != nil {
		return r.createRefreshTokenErr
	}
	if !r.discardRefreshTokens {
		r.refreshTokens = append(r.refreshTokens, token)
	}
	return nil
}

func (r *faultExternalAuthRepository) GetAuthRefreshTokenByHash(_ context.Context, _, tokenHash string) (identitymodel.AuthRefreshToken, bool, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	r.getRefreshTokenCalls++
	if r.getRefreshTokenErr != nil && (r.getRefreshTokenErrAt == 0 || r.getRefreshTokenCalls == r.getRefreshTokenErrAt) {
		return identitymodel.AuthRefreshToken{}, false, r.getRefreshTokenErr
	}
	for _, token := range r.refreshTokens {
		if token.TokenHash == tokenHash {
			return token, true, nil
		}
	}
	return identitymodel.AuthRefreshToken{}, false, nil
}

func (r *faultExternalAuthRepository) RevokeAuthRefreshToken(_ context.Context, _, tokenID, _, _ string) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.revokeRefreshTokenErr != nil {
		return r.revokeRefreshTokenErr
	}
	r.revokedRefreshTokens = append(r.revokedRefreshTokens, tokenID)
	return nil
}

func (r *faultExternalAuthRepository) ListAuthRefreshTokensForUser(_ context.Context, _, userID string) ([]identitymodel.AuthRefreshToken, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	result := []identitymodel.AuthRefreshToken{}
	for _, token := range r.refreshTokens {
		if token.UserID == userID {
			result = append(result, token)
		}
	}
	return result, nil
}

func (r *faultExternalAuthRepository) RevokeAuthRefreshTokensForUser(_ context.Context, _, userID, revokedAt string) (int, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	count := 0
	for index := range r.refreshTokens {
		if r.refreshTokens[index].UserID == userID && r.refreshTokens[index].RevokedAt == "" {
			r.refreshTokens[index].RevokedAt = revokedAt
			count++
		}
	}
	return count, nil
}

func (r *faultExternalAuthRepository) RotateAuthRefreshToken(_ context.Context, _ string, tokenID, revokedAt string, replacement identitymodel.AuthRefreshToken) (bool, error) {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.revokeRefreshTokenErr != nil {
		return false, r.revokeRefreshTokenErr
	}
	for index := range r.refreshTokens {
		if r.refreshTokens[index].ID != tokenID || r.refreshTokens[index].RevokedAt != "" {
			continue
		}
		r.refreshTokens[index].RevokedAt = revokedAt
		r.refreshTokens[index].ReplacedByID = replacement.ID
		r.revokedRefreshTokens = append(r.revokedRefreshTokens, tokenID)
		if !r.discardRefreshTokens {
			r.refreshTokens = append(r.refreshTokens, replacement)
		}
		return true, nil
	}
	return false, nil
}
