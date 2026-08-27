package service

import authpolicy "github.com/domainry/domainry-identity/internal/domain/auth/policy"

import (
	"errors"
	"strings"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordPolicyValidation(t *testing.T) {
	auth, _, _ := newFaultAuthDomainService()
	auth.passwordPolicy = authpolicy.AuthPasswordPolicy{MinLength: 8, RequireUpper: true, RequireLower: true, RequireNumber: true, RequireSymbol: true}

	for _, testCase := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "too short", password: "Aa1!", wantErr: true},
		{name: "upper required", password: "lowercase1!", wantErr: true},
		{name: "lower required", password: "UPPERCASE1!", wantErr: true},
		{name: "number required", password: "NoNumbers!", wantErr: true},
		{name: "symbol required", password: "NoSymbols1", wantErr: true},
		{name: "valid", password: "ValidPass1!"},
		{name: "unicode symbol", password: "ValidPass1€"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := auth.validatePassword(testCase.password)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("validate %q: want error=%v, got %v", testCase.password, testCase.wantErr, err)
			}
		})
	}

	auth.passwordPolicy.MinLength = 0
	if err := auth.validatePassword("1234567"); err == nil {
		t.Fatal("zero minimum length must fall back to eight characters")
	}
	auth.passwordPolicy = authpolicy.AuthPasswordPolicy{}
	if err := auth.validatePassword("Valid Pass1"); err != nil {
		t.Fatalf("password containing non-symbol whitespace: %v", err)
	}
}

func TestCredentialLockState(t *testing.T) {
	now := time.Now().UTC()
	for _, testCase := range []struct {
		name        string
		lockedUntil string
		want        bool
	}{
		{name: "not locked"},
		{name: "invalid timestamp", lockedUntil: "invalid"},
		{name: "expired lock", lockedUntil: now.Add(-time.Minute).Format(time.RFC3339)},
		{name: "active lock", lockedUntil: now.Add(time.Minute).Format(time.RFC3339), want: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := credentialLocked(identitymodel.IdentityCredential{LockedUntil: testCase.lockedUntil}, now); got != testCase.want {
				t.Fatalf("want locked=%v, got %v", testCase.want, got)
			}
		})
	}
}

func TestBootstrapCredentialProvisioning(t *testing.T) {
	fault := errors.New("bootstrap credential fault")

	t.Run("nil repository", func(t *testing.T) {
		_, identityRepository, _ := newFaultAuthDomainService()
		auth := NewAuthDomainService(identityRepository, nil, "secret", "ValidPass1!", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
		if err := auth.EnsureBootstrapCredential(t.Context(), "default"); err != nil {
			t.Fatalf("nil auth repository: %v", err)
		}
	})

	t.Run("identity lookup failure", func(t *testing.T) {
		auth, identityRepository, _ := newFaultAuthDomainService()
		identityRepository.listUsersErr = fault
		assertExternalAuthFault(t, auth.EnsureBootstrapCredential(t.Context(), "default"), fault)
	})

	t.Run("admin missing", func(t *testing.T) {
		auth, _, _ := newFaultAuthDomainService()
		if err := auth.EnsureBootstrapCredential(t.Context(), "default"); err != nil {
			t.Fatalf("missing admin: %v", err)
		}
	})

	t.Run("credential read failure", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("admin", "admin@example.com")}
		authRepository.getCredentialErr = fault
		assertExternalAuthFault(t, auth.EnsureBootstrapCredential(t.Context(), "default"), fault)
	})

	t.Run("credential already exists", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("admin", "admin@example.com")}
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"admin": passwordCredential(t, "admin", "ChangedPass1!")}
		credential := authRepository.credentials["admin"]
		credential.FailedLoginCount = 4
		credential.LockedUntil = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		credential.MustChangePassword = true
		authRepository.credentials["admin"] = credential
		if err := auth.EnsureBootstrapCredential(t.Context(), "default"); err != nil {
			t.Fatalf("existing credential: %v", err)
		}
		preserved := authRepository.credentials["admin"]
		if bcrypt.CompareHashAndPassword([]byte(preserved.PasswordHash), []byte("ChangedPass1!")) != nil ||
			preserved.FailedLoginCount != 4 || preserved.LockedUntil != credential.LockedUntil || !preserved.MustChangePassword {
			t.Fatalf("existing system seed credential was overwritten: %#v", preserved)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("admin", "admin@example.com")}
		authRepository.upsertCredentialErr = fault
		assertExternalAuthFault(t, auth.EnsureBootstrapCredential(t.Context(), "default"), fault)
	})

	t.Run("success", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		identityRepository.users = []identitymodel.IdentityUser{activeExternalIdentityUser("admin", "admin@example.com")}
		if err := auth.EnsureBootstrapCredential(t.Context(), "default"); err != nil {
			t.Fatalf("provision bootstrap credential: %v", err)
		}
		if credential := authRepository.credentials[SystemSeedAdminUserID]; credential.PasswordHash == "" || !credential.MustChangePassword ||
			bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte("Password@2026")) != nil {
			t.Fatalf("unexpected bootstrap credential: %#v", credential)
		}
	})
}

func TestUserCredentialBatchProvisioning(t *testing.T) {
	fault := errors.New("batch credential fault")
	users := []identitymodel.IdentityUser{
		activeExternalIdentityUser("active", "active@example.com"),
		{ID: "disabled", Status: identitymodel.IdentityStatusDisabled},
		{ID: " ", Status: identitymodel.IdentityStatusActive},
	}

	t.Run("nil repository", func(t *testing.T) {
		_, identityRepository, _ := newFaultAuthDomainService()
		auth := NewAuthDomainService(identityRepository, nil, "secret", "ValidPass1!", 0, 0, 0, 0, 0, 0, authpolicy.AuthPasswordPolicy{})
		if err := auth.EnsureCredentialsForUsers(t.Context(), "default", users); err != nil {
			t.Fatalf("nil auth repository: %v", err)
		}
	})

	t.Run("read and write failures", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.getCredentialErr = fault
		assertExternalAuthFault(t, auth.EnsureCredentialsForUsers(t.Context(), "default", users), fault)
		authRepository.getCredentialErr = nil
		authRepository.upsertCredentialErr = fault
		assertExternalAuthFault(t, auth.EnsureCredentialsForUsers(t.Context(), "default", users), fault)
	})

	t.Run("existing and new credentials", func(t *testing.T) {
		auth, _, authRepository := newFaultAuthDomainService()
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"existing": passwordCredential(t, "existing", "ChangedPass1!")}
		provisionUsers := append(users, activeExternalIdentityUser("existing", "existing@example.com"))
		if err := auth.EnsureCredentialsForUsers(t.Context(), "default", provisionUsers); err != nil {
			t.Fatalf("provision user credentials: %v", err)
		}
		if len(authRepository.credentials) != 2 || !authRepository.credentials["active"].MustChangePassword || authRepository.credentials["existing"].MustChangePassword ||
			bcrypt.CompareHashAndPassword([]byte(authRepository.credentials["active"].PasswordHash), []byte("Password@2026")) != nil ||
			bcrypt.CompareHashAndPassword([]byte(authRepository.credentials["existing"].PasswordHash), []byte("ChangedPass1!")) != nil {
			t.Fatalf("unexpected provisioned credentials: %#v", authRepository.credentials)
		}
	})
}

func TestPasswordLoginAndMutationLifecycle(t *testing.T) {
	password := "CurrentPass1!"
	newPassword := "NewPassword2!"

	t.Run("successful login and password change", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": passwordCredential(t, "user", password)}
		session, err := auth.Login(t.Context(), "default", user.Email, password)
		if err != nil || session.AccessToken == "" {
			t.Fatalf("login: session=%#v err=%v", session, err)
		}
		if err := auth.ChangePassword(t.Context(), "default", user.ID, password, newPassword); err != nil {
			t.Fatalf("change password: %v", err)
		}
		if bcrypt.CompareHashAndPassword([]byte(authRepository.credentials[user.ID].PasswordHash), []byte(newPassword)) != nil {
			t.Fatal("new password was not persisted")
		}
	})

	t.Run("login validation and lockout", func(t *testing.T) {
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.users = []identitymodel.IdentityUser{user}
		if _, err := auth.Login(t.Context(), "default", "missing", password); err == nil {
			t.Fatal("missing login must fail")
		}
		user.Status = identitymodel.IdentityStatusDisabled
		identityRepository.users = []identitymodel.IdentityUser{user}
		if _, err := auth.Login(t.Context(), "default", user.Email, password); err == nil {
			t.Fatal("disabled login must fail")
		}
		user.Status = identitymodel.IdentityStatusActive
		identityRepository.users = []identitymodel.IdentityUser{user}
		if _, err := auth.Login(t.Context(), "default", user.Email, password); err == nil {
			t.Fatal("missing credential must fail")
		}
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": passwordCredential(t, "user", password)}
		credential := authRepository.credentials["user"]
		credential.LockedUntil = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
		authRepository.credentials["user"] = credential
		if _, err := auth.Login(t.Context(), "default", user.Email, password); err == nil {
			t.Fatal("locked login must fail")
		}
		credential.LockedUntil = ""
		authRepository.credentials["user"] = credential
		if _, err := auth.Login(t.Context(), "default", user.Email, "wrong"); err == nil {
			t.Fatal("wrong password must fail")
		}
	})

	t.Run("repository failures", func(t *testing.T) {
		fault := errors.New("login repository fault")
		auth, identityRepository, authRepository := newFaultAuthDomainService()
		user := activeExternalIdentityUser("user", "user@example.com")
		identityRepository.listUsersErr = fault
		_, err := auth.Login(t.Context(), "default", user.Email, password)
		assertExternalAuthFault(t, err, fault)
		identityRepository.listUsersErr = nil
		identityRepository.users = []identitymodel.IdentityUser{user}
		authRepository.getCredentialErr = fault
		_, err = auth.Login(t.Context(), "default", user.Email, password)
		assertExternalAuthFault(t, err, fault)
		authRepository.getCredentialErr = nil
		authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": passwordCredential(t, "user", password)}
		authRepository.recordLoginFailureErr = fault
		_, err = auth.Login(t.Context(), "default", user.Email, "wrong")
		assertExternalAuthFault(t, err, fault)
		authRepository.recordLoginFailureErr = nil
		authRepository.recordLoginSuccessErr = fault
		_, err = auth.Login(t.Context(), "default", user.Email, password)
		assertExternalAuthFault(t, err, fault)
		authRepository.recordLoginSuccessErr = nil
		identityRepository.listAssignmentsErr = fault
		_, err = auth.Login(t.Context(), "default", user.Email, password)
		assertExternalAuthFault(t, err, fault)
	})
}

func TestPasswordMutationFailuresAndReset(t *testing.T) {
	fault := errors.New("password mutation fault")
	password := "CurrentPass1!"
	newPassword := "NewPassword2!"

	auth, identityRepository, authRepository := newFaultAuthDomainService()
	user := activeExternalIdentityUser("user", "user@example.com")
	identityRepository.users = []identitymodel.IdentityUser{user}
	authRepository.credentials = map[string]identitymodel.IdentityCredential{"user": passwordCredential(t, "user", password)}

	for _, request := range []struct{ userID, current, next string }{
		{current: password, next: newPassword},
		{userID: user.ID, next: newPassword},
		{userID: user.ID, current: password},
		{userID: user.ID, current: password, next: "weak"},
	} {
		if err := auth.ChangePassword(t.Context(), "default", request.userID, request.current, request.next); err == nil {
			t.Fatalf("invalid password change must fail: %#v", request)
		}
	}

	authRepository.getCredentialErr = fault
	assertExternalAuthFault(t, auth.ChangePassword(t.Context(), "default", user.ID, password, newPassword), fault)
	authRepository.getCredentialErr = nil
	delete(authRepository.credentials, user.ID)
	if err := auth.ChangePassword(t.Context(), "default", user.ID, password, newPassword); err == nil {
		t.Fatal("missing credential must fail")
	}
	authRepository.credentials[user.ID] = passwordCredential(t, user.ID, password)
	credential := authRepository.credentials[user.ID]
	credential.LockedUntil = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	authRepository.credentials[user.ID] = credential
	if err := auth.ChangePassword(t.Context(), "default", user.ID, password, newPassword); err == nil {
		t.Fatal("locked credential must fail")
	}
	credential.LockedUntil = ""
	authRepository.credentials[user.ID] = credential
	if err := auth.ChangePassword(t.Context(), "default", user.ID, "wrong", newPassword); err == nil {
		t.Fatal("incorrect current password must fail")
	}

	for _, request := range []struct {
		userID, password string
	}{
		{password: newPassword},
		{userID: user.ID},
		{userID: user.ID, password: "weak"},
	} {
		if err := auth.ResetPassword(t.Context(), "default", request.userID, request.password, true); err == nil {
			t.Fatalf("invalid reset must fail: %#v", request)
		}
	}
	identityRepository.listUsersErr = fault
	assertExternalAuthFault(t, auth.ResetPassword(t.Context(), "default", user.ID, newPassword, true), fault)
	identityRepository.listUsersErr = nil
	identityRepository.users = nil
	if err := auth.ResetPassword(t.Context(), "default", user.ID, newPassword, true); err == nil {
		t.Fatal("missing reset user must fail")
	}
	user.Status = identitymodel.IdentityStatusDisabled
	identityRepository.users = []identitymodel.IdentityUser{user}
	if err := auth.ResetPassword(t.Context(), "default", user.ID, newPassword, true); err == nil {
		t.Fatal("disabled reset user must fail")
	}
	user.Status = identitymodel.IdentityStatusActive
	identityRepository.users = []identitymodel.IdentityUser{user}
	if err := auth.ResetPassword(t.Context(), "default", user.ID, newPassword, true); err != nil {
		t.Fatalf("reset active user: %v", err)
	}
	if !authRepository.credentials[user.ID].MustChangePassword {
		t.Fatal("reset must preserve the requested change-password flag")
	}
}

func TestPasswordStorageFailurePaths(t *testing.T) {
	fault := errors.New("password storage fault")
	auth, _, authRepository := newFaultAuthDomainService()

	if err := auth.setPassword(t.Context(), "default", "user", strings.Repeat("a", 73), false); err == nil {
		t.Fatal("expected bcrypt input limit failure")
	}
	authRepository.getCredentialErr = fault
	assertExternalAuthFault(t, auth.setPassword(t.Context(), "default", "user", "ValidPass1!", false), fault)
	authRepository.getCredentialErr = nil
	authRepository.upsertCredentialErr = fault
	assertExternalAuthFault(t, auth.setPassword(t.Context(), "default", "user", "ValidPass1!", false), fault)

	authRepository.upsertCredentialErr = nil
	authRepository.recordLoginFailureErr = fault
	auth.maxLoginFailures = 2
	credential := identitymodel.IdentityCredential{UserID: "user"}
	if err := auth.recordLoginFailure(t.Context(), "default", credential); !errors.Is(err, fault) {
		t.Fatalf("record first failure: %v", err)
	}
	credential.FailedLoginCount = 1
	if err := auth.recordLoginFailure(t.Context(), "default", credential); !errors.Is(err, fault) {
		t.Fatalf("record locking failure: %v", err)
	}
	auth.maxLoginFailures = 0
	if err := auth.recordLoginFailure(t.Context(), "default", credential); !errors.Is(err, fault) {
		t.Fatalf("record failure with lockout disabled: %v", err)
	}
}

func TestIssueInitialPassword(t *testing.T) {
	auth, _, authRepository := newFaultAuthDomainService()
	password, err := auth.IssueInitialPassword(t.Context(), "default", " user ")
	if err != nil {
		t.Fatalf("issue initial password: %v", err)
	}
	credential := authRepository.credentials["user"]
	if password == "" || password == "Password@2026" || len(password) < 24 || !credential.MustChangePassword || bcrypt.CompareHashAndPassword([]byte(credential.PasswordHash), []byte(password)) != nil {
		t.Fatalf("unexpected initial credential: password=%q credential=%#v", password, credential)
	}
	authRepository.upsertCredentialErr = errors.New("write failed")
	if _, err := auth.IssueInitialPassword(t.Context(), "default", "user"); err == nil {
		t.Fatal("expected initial password persistence failure")
	}
}

func passwordCredential(t *testing.T, userID string, password string) identitymodel.IdentityCredential {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return identitymodel.IdentityCredential{UserID: userID, PasswordHash: string(hash)}
}
