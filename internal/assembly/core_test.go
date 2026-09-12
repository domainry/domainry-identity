package assembly

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	auditcontract "github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestSharedPasswordLoginBoundaryAuditsSuccessAndFailureWithoutCredentials(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", filepath.Join(t.TempDir(), "identity.db")
	cfg.IdentityWorkspaceID, cfg.AuthAudience = "workspace-primary", "runtime-app"
	cfg.AuthJWTSecret, cfg.AuthDefaultPassword = "login-audit-signing-secret", "AdminPassword1!"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.CloseContext(t.Context()) })
	application := identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: identitysdk.ApplicationKey(cfg.AuthAudience)}
	if _, err := core.Binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}

	failedCtx := requestcontext.WithRequestID(t.Context(), "login-failed-request")
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := core.Binding.Authentication().LoginWithPassword(failedCtx, identitysdk.PasswordLoginRequest{
			WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "admin@example.com", Password: "WrongPassword1!",
		}); err == nil {
			t.Fatal("wrong password accepted")
		}
	}
	successCtx := requestcontext.WithRequestID(t.Context(), "login-success-request")
	if _, err := core.Binding.Authentication().LoginWithPassword(successCtx, identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "admin@example.com", Password: cfg.AuthDefaultPassword,
	}); err != nil {
		t.Fatal(err)
	}

	assertEvent := func(requestID, eventName string) auditcontract.Event {
		t.Helper()
		events, err := core.AuditBinding.Reader().List(t.Context(), cfg.IdentityWorkspaceID, auditcontract.Query{RequestID: requestID, Limit: 10})
		if err != nil || len(events) != 1 {
			t.Fatalf("request=%s events=%#v err=%v", requestID, events, err)
		}
		if events[0].Event != eventName || auditcontract.ClassifyEvent(events[0]) != auditcontract.EventClassOperations {
			t.Fatalf("request=%s event=%#v", requestID, events[0])
		}
		return events[0]
	}
	failed := assertEvent("login-failed-request", "auth_login_failed")
	if failed.ActorID != "anonymous" || failed.Metadata["result"] != "failed" || failed.Metadata["reason"] != "invalid_credentials" || len(strings.TrimSpace(failed.Metadata["login_fingerprint_sha256"].(string))) != 64 {
		t.Fatalf("failed login audit=%#v", failed)
	}
	failedJSON, _ := json.Marshal(failed)
	if strings.Contains(string(failedJSON), "admin@example.com") || strings.Contains(string(failedJSON), "WrongPassword1!") || strings.Contains(strings.ToLower(string(failedJSON)), "access_token") || strings.Contains(strings.ToLower(string(failedJSON)), "refresh_token") {
		t.Fatalf("failed login audit leaked credentials: %s", failedJSON)
	}
	succeeded := assertEvent("login-success-request", "auth_login_succeeded")
	if succeeded.ActorID == "" || succeeded.ActorID == "anonymous" || succeeded.RoleKey == "" || succeeded.Metadata["result"] != "success" || succeeded.Metadata["authentication_method"] != "password" || succeeded.Metadata["application_key"] != cfg.AuthAudience {
		t.Fatalf("successful login audit=%#v", succeeded)
	}

	const changedPassword = "ChangedAdminPassword2!"
	if err := core.Auth.ChangePassword(t.Context(), cfg.IdentityWorkspaceID, succeeded.ActorID, cfg.AuthDefaultPassword, changedPassword); err != nil {
		t.Fatal(err)
	}
	enrollment, err := core.Auth.ManageTOTP(t.Context(), cfg.IdentityWorkspaceID, succeeded.ActorID, authmodel.TOTPRequest{Operation: "enroll", CurrentPassword: changedPassword})
	if err != nil {
		t.Fatal(err)
	}
	step := time.Now().Unix() / 30
	if _, err := core.Auth.ManageTOTP(t.Context(), cfg.IdentityWorkspaceID, succeeded.ActorID, authmodel.TOTPRequest{Operation: "confirm", State: enrollment.State, Code: coreTestAuthenticatorCode(t, enrollment.SetupKey, step-1)}); err != nil {
		t.Fatal(err)
	}
	if err := core.AuthStore.UpsertIdentityMFAFactor(t.Context(), cfg.IdentityWorkspaceID, identitymodel.IdentityMFAFactor{ID: "login-policy", UserID: succeeded.ActorID, Type: "otp", Provider: "sms", Status: "active", VerifiedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	core.ProviderConfiguration.AddConfig(authmodel.AuthProviderConfig{Key: "sms", Type: "otp", Enabled: true, AllowedPurposes: []string{authmodel.AuthChallengePurposeLoginMFA}})
	challengeCtx := requestcontext.WithRequestID(t.Context(), "login-challenge-request")
	challenge, err := core.Binding.(identitysdk.ChallengeAuthenticationBinding).ChallengeAuthentication().LoginWithPasswordOutcome(challengeCtx, identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "admin@example.com", Password: changedPassword,
	})
	if err != nil || challenge.Status != identitysdk.AuthenticationStatusChallengeRequired || challenge.Session != nil || challenge.Challenge == nil {
		t.Fatalf("challenge=%#v err=%v", challenge, err)
	}
	challengeEvents, err := core.AuditBinding.Reader().List(t.Context(), cfg.IdentityWorkspaceID, auditcontract.Query{RequestID: "login-challenge-request", Limit: 10})
	if err != nil || len(challengeEvents) != 0 {
		t.Fatalf("challenge was audited as terminal login: events=%#v err=%v", challengeEvents, err)
	}
	failedOTPContext := requestcontext.WithRequestID(t.Context(), "login-otp-failed-request")
	if _, err := core.Binding.(identitysdk.ChallengeAuthenticationBinding).ChallengeAuthentication().VerifyOTPOutcome(failedOTPContext, identitysdk.VerifyOTPRequest{
		WorkspaceID: application.WorkspaceID, Provider: challenge.Challenge.Provider, State: challenge.Challenge.State, Code: "000000",
	}); err == nil {
		t.Fatal("invalid OTP accepted")
	}
	failedOTP := assertEvent("login-otp-failed-request", "auth_login_failed")
	if failedOTP.ActorID != "anonymous" || failedOTP.Metadata["authentication_method"] != "otp" || failedOTP.Metadata["result"] != "failed" {
		t.Fatalf("failed OTP audit=%#v", failedOTP)
	}
	otpContext := requestcontext.WithRequestID(t.Context(), "login-otp-success-request")
	otp, err := core.Binding.(identitysdk.ChallengeAuthenticationBinding).ChallengeAuthentication().VerifyOTPOutcome(otpContext, identitysdk.VerifyOTPRequest{
		WorkspaceID: application.WorkspaceID, Provider: challenge.Challenge.Provider, State: challenge.Challenge.State, Code: coreTestAuthenticatorCode(t, enrollment.SetupKey, step),
	})
	if err != nil || otp.Session == nil {
		t.Fatalf("OTP outcome=%#v err=%v", otp, err)
	}
	otpEvent := assertEvent("login-otp-success-request", "auth_login_succeeded")
	if otpEvent.ActorID != succeeded.ActorID || otpEvent.Metadata["authentication_method"] != "otp" || otpEvent.Metadata["provider"] != string(challenge.Challenge.Provider) || otpEvent.Metadata["application_key"] != cfg.AuthAudience {
		t.Fatalf("successful OTP audit=%#v", otpEvent)
	}
}

func coreTestAuthenticatorCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], uint64(step))
	hash := hmac.New(sha1.New, key)
	_, _ = hash.Write(data[:])
	digest := hash.Sum(nil)
	offset := digest[19] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
}

func TestBindingRuntimeAssemblyReturnsDirectSDKBinding(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve server test source")
	}
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment = "development"
	cfg.DatabaseDriver = "sqlite"
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assembled, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = assembled.CloseContext(t.Context()) })
	if assembled.Binding == nil {
		t.Fatal("binding-only assembly returned no SDK Binding")
	}
}

func TestAssemblySeparatesApplicationRegistrationFromPermissionReconcile(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", filepath.Join(t.TempDir(), "identity.db")
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.CloseContext(t.Context()) })

	application := identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: "gym"}
	if _, err := core.Binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application, RedirectURLs: []string{"https://gym.example.test/callback"}}); err != nil {
		t.Fatalf("register application: %v", err)
	}
	permissionRequest, err := identitysdk.NewPermissionReconcileRequest(application, "application:gym", "", []identitysdk.PermissionDefinition{{PermissionKey: "access_session.read", ResourceKey: "access_session", OperationKey: "read", Label: "Read access sessions", Category: "Gym", SourceKind: "object_action"}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := core.Binding.Permissions().Reconcile(t.Context(), permissionRequest)
	if err != nil {
		t.Fatalf("reconcile application permission: %v", err)
	}
	if receipt.SourceOwner != "application:gym" || receipt.Inserted != 1 {
		t.Fatalf("permission receipt=%+v", receipt)
	}
	definitions, err := core.PermissionCatalog.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, definition := range definitions {
		found = found || definition.Key == "access_session.read" && definition.SourceOwner == "application:gym"
	}
	if !found {
		t.Fatalf("application-owned permission missing from current definitions: %+v", definitions)
	}
}

func TestColdStartLoadsPublishedRoleDefinitions(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	dbPath := filepath.Join(t.TempDir(), "identity.db")
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", dbPath
	cfg.IdentityWorkspaceID = "workspace-primary"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")

	open := func() *Core {
		store, err := database.OpenContext(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		core, err := New(t.Context(), cfg, store, Options{WorkspaceID: cfg.IdentityWorkspaceID})
		if err != nil {
			t.Fatal(err)
		}
		return core
	}
	first := open()
	payload, _ := json.Marshal(identitymodel.RoleSchema{Key: "member", Name: "Member", Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, "membership.read", "booking.create")})
	empty := ""
	_, err := first.MetadataStore.ApplyDefinitionMutations(t.Context(), identitymodel.NewSystemScope(identitymodel.SystemScopeInstallation, "test published role"), []metadatamodel.MetadataDefinitionMutation{{
		Operation: "create", ResourceType: "role", ResourceKey: "member",
		Request: metadatamodel.MetadataDefinitionUpsertRequest{ExpectedSchemaHash: &empty, Payload: payload},
	}}, nil, &metadatamodel.MetadataDefinitionPublication{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	second := open()
	defer second.CloseContext(t.Context())
	definition, found := second.Identity.PublishedRoleDefinition(t.Context(), "member")
	if !found || len(definition.Permissions) != 2 || definition.Permissions[0].PermissionKey != "membership.read" {
		t.Fatalf("cold-start role definition=%#v found=%v", definition, found)
	}
	found = false
	for _, role := range second.MetadataRuntime.Schema().Roles {
		found = found || role.Key == "member"
	}
	if !found {
		t.Fatal("cold-start metadata snapshot omitted published member role")
	}
}
