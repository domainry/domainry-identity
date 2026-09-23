package assembly

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/apperror"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	authrepository "github.com/domainry/domainry-identity/internal/domain/auth/repository"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitytransaction "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestHandlerDeliveryIsAtomicIdempotentGovernedAndRestartSafe(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	databasePath := filepath.Join(t.TempDir(), "identity-handler-delivery.db")
	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", databasePath
	cfg.IdentityWorkspaceID, cfg.AuthAudience = "workspace-primary", "runtime-app"
	cfg.AuthJWTSecret, cfg.AuthDefaultPassword = "handler-delivery-signing-secret", "AdminPassword1!"
	cfg.ManifestPath = filepath.Join(projectRoot, "domainry.template.json")
	manifest, err := loadManifest(cfg.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Roles = append(manifest.Roles,
		identitymodel.RoleSchema{
			Key: "handler_operator", Name: "Handler operator", Audience: identitymodel.IdentityRoleAudienceAny,
			AssignmentMode: identitymodel.IdentityRoleAssignmentManual, GrantableRoleKeys: []string{"employee"},
			Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
				identitycontract.IdentityHandlerDeliveryCreatePermission, identitycontract.IdentityHandlerDeliveryUpdatePermission,
				identitycontract.IdentityHandlerDeliveryDisablePermission, identitycontract.IdentityHandlerDeliveryResolvePermission,
			),
		},
		identitymodel.RoleSchema{
			Key: "crud_operator", Name: "CRUD operator", Audience: identitymodel.IdentityRoleAudienceAny,
			AssignmentMode: identitymodel.IdentityRoleAssignmentManual, GrantableRoleKeys: []string{"employee"},
			Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
				identitycontract.IdentityUsersCreatePermission, identitycontract.IdentityUsersUpdatePermission,
				identitycontract.IdentityUsersDisablePermission, identitycontract.IdentityUsersGetPermission,
				identitycontract.IdentityUserRoleAssignmentsAccountUpdatePermission,
				identitycontract.IdentityUserRoleAssignmentsListPermission, identitycontract.IdentityActionProfileBindingsCommand,
			),
		},
		identitymodel.RoleSchema{
			Key: "nightpos_staff", Name: "NightPOS staff", Audience: identitymodel.IdentityRoleAudienceAny,
			AssignmentMode: identitymodel.IdentityRoleAssignmentManual,
			Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll,
				identitycontract.IdentityHandlerDeliveryResolvePermission,
			),
		},
		identitymodel.RoleSchema{Key: "employee", Name: "Employee", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	)

	open := func() (*Core, *database.IdentityStore) {
		store, err := database.OpenContext(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnsureSchema(t.Context()); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		core, err := NewWithManifest(t.Context(), cfg, store, manifest, Options{WorkspaceID: cfg.IdentityWorkspaceID})
		if err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		installAndBindTestSharedOperations(t, core, store)
		return core, store
	}
	core, store := open()
	application := identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: identitysdk.ApplicationKey(cfg.AuthAudience)}
	if _, err := core.Binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}
	adminSession, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "admin@example.com", Password: cfg.AuthDefaultPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = adminSession
	handlerSession, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "handler_operator@example.com", Password: cfg.AuthDefaultPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := core.Binding.(identitysdk.HandlerDeliveryBinding).HandlerDelivery()
	create := identitysdk.HandlerDeliveryRequest{
		ContractVersion: identitysdk.HandlerDeliveryContractVersionV1, AccessToken: handlerSession.AccessToken, IdempotencyKey: "employee-create-1",
		User: identitysdk.HandlerUserMutation{Operation: identitysdk.HandlerUserCreate, LoginMode: identitysdk.HandlerLoginPassword, User: identitysdk.User{
			ID: "employee-1", Name: "Employee One", Email: "employee-1@example.test", AccountType: "human", Status: "active",
		}}, RoleKeys: []string{"employee"},
	}
	missingLoginMode := create
	missingLoginMode.IdempotencyKey, missingLoginMode.User.LoginMode = "missing-login-mode", ""
	missingLoginMode.User.User.ID, missingLoginMode.User.User.Email = "missing-login-mode", "missing-login-mode@example.test"
	if _, err := handler.DeliverIdentity(t.Context(), missingLoginMode); apperror.CodeOf(err) != "backend.identity.handler_delivery_login_mode_invalid" {
		t.Fatalf("create accepted missing login mode: %v", err)
	}
	created, err := handler.DeliverIdentity(t.Context(), create)
	if err != nil || created.Replayed || created.User.Version != 1 || len(created.RoleKeys) != 1 || created.InitialCredential == nil ||
		created.InitialCredential.InitialPassword == "" || !created.InitialCredential.MustChangePassword || !created.InitialCredential.NoStore {
		if sdkErr, ok := err.(*identitysdk.Error); ok {
			t.Logf("handler delivery cause: %v", sdkErr.Cause)
		}
		t.Fatalf("created=%+v err=%#v", created, err)
	}
	replayed, err := handler.DeliverIdentity(t.Context(), create)
	if err != nil || !replayed.Replayed || replayed.DeliveryID != created.DeliveryID || replayed.InitialCredential != nil {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	var persistedResult string
	if err := store.DB().QueryRowContext(t.Context(), `SELECT result_json FROM _operations WHERE workspace_id = ? AND owner = 'identity' AND kind = 'identity.handler_delivery' AND idempotency_key = ?`, cfg.IdentityWorkspaceID, create.IdempotencyKey).Scan(&persistedResult); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persistedResult, created.InitialCredential.InitialPassword) || strings.Contains(strings.ToLower(persistedResult), "password") || strings.Contains(persistedResult, "$2") {
		t.Fatalf("credential persisted in HandlerDelivery receipt: %s", persistedResult)
	}
	var createAudits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND event = ? AND object_key = ? AND record_id = ?`, cfg.IdentityWorkspaceID, "identity.handler_delivery.create", "identity_user", "employee-1").Scan(&createAudits); err != nil || createAudits != 1 {
		t.Fatalf("create audit count=%d err=%v", createAudits, err)
	}
	reused := create
	reused.User.User.Name = "Different payload"
	if _, err := handler.DeliverIdentity(t.Context(), reused); apperror.CodeOf(err) != "backend.idempotency_key_reused" {
		t.Fatalf("same key with different payload err=%v", err)
	}
	stale := create
	stale.IdempotencyKey = "employee-update-stale"
	stale.User.Operation = identitysdk.HandlerUserUpdate
	stale.User.LoginMode = ""
	stale.User.ExpectedVersion = 99
	if _, err := handler.DeliverIdentity(t.Context(), stale); apperror.CodeOf(err) != "backend.identity.user_version_conflict" {
		t.Fatalf("stale CAS err=%v", err)
	}
	passwordOnUpdate := stale
	passwordOnUpdate.IdempotencyKey, passwordOnUpdate.User.LoginMode = "password-on-update", identitysdk.HandlerLoginPassword
	if _, err := handler.DeliverIdentity(t.Context(), passwordOnUpdate); apperror.CodeOf(err) != "backend.identity.handler_delivery_login_mode_invalid" {
		t.Fatalf("update accepted password login mode: %v", err)
	}

	staffSession, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "nightpos_staff@example.com", Password: cfg.AuthDefaultPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := handler.ResolveBoundIdentity(t.Context(), identitysdk.HandlerBoundIdentityRequest{
		ContractVersion: identitysdk.HandlerDeliveryContractVersionV1, AccessToken: staffSession.AccessToken, UserID: "employee-1",
	})
	if err != nil || projection.DisplayName != "Employee One" || !projection.Active || len(projection.RoleKeys) != 1 || projection.RoleKeys[0] != "employee" {
		t.Fatalf("projection=%+v err=%v", projection, err)
	}
	projectionJSON, err := json.Marshal(projection)
	if err != nil || strings.Contains(string(projectionJSON), "employee-1@example.test") || strings.Contains(string(projectionJSON), "credential") || strings.Contains(string(projectionJSON), "password") || strings.Contains(string(projectionJSON), "phone") {
		t.Fatalf("minimal projection leaked private fields: %s err=%v", projectionJSON, err)
	}
	staffWrite := create
	staffWrite.AccessToken, staffWrite.IdempotencyKey = staffSession.AccessToken, "staff-write-attempt"
	staffWrite.User.User.ID, staffWrite.User.User.Email = "staff-write", "staff-write@example.test"
	if _, err := handler.DeliverIdentity(t.Context(), staffWrite); apperror.CodeOf(err) != "backend.identity.data_scope_denied" {
		t.Fatalf("resolve-only staff grant reached HandlerDelivery write: %v", err)
	}

	narrowPrincipal, err := core.Identity.ResolvePrincipal(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), "handler_operator_user")
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Identity.CreateUserWithinDataScope(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), identitymodel.IdentityUser{
		ID: "crud-bypass", Name: "CRUD bypass", Email: "crud-bypass@example.test", Status: identitymodel.IdentityStatusActive,
	}, narrowPrincipal, identitycontract.IdentityUsersCreatePermission); apperror.CodeOf(err) != "auth.permission_denied" {
		t.Fatalf("purpose-specific Handler grant reached generic CRUD: %v", err)
	}
	crudSession, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "crud_operator@example.com", Password: cfg.AuthDefaultPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	crudOnly := create
	crudOnly.AccessToken, crudOnly.IdempotencyKey, crudOnly.User.User.ID, crudOnly.User.User.Email = crudSession.AccessToken, "crud-only-handler-attempt", "crud-only-user", "crud-only@example.test"
	if _, err := handler.DeliverIdentity(t.Context(), crudOnly); apperror.CodeOf(err) != "backend.identity.data_scope_denied" {
		t.Fatalf("generic CRUD grant reached HandlerDelivery: %v", err)
	}
	ceiling := create
	ceiling.IdempotencyKey, ceiling.User.User.ID, ceiling.User.User.Email = "role-ceiling-attempt", "role-ceiling-user", "role-ceiling@example.test"
	ceiling.RoleKeys = []string{"organization_administrator"}
	if _, err := handler.DeliverIdentity(t.Context(), ceiling); apperror.CodeOf(err) != "backend.identity.role_grant_ceiling_exceeded" {
		t.Fatalf("HandlerDelivery bypassed role ceiling: %v", err)
	}
	for _, rejectedID := range []string{"missing-login-mode", "staff-write", "crud-bypass", "crud-only-user", "role-ceiling-user"} {
		if _, found, err := core.Identity.FindUser(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), rejectedID); err != nil || found {
			t.Fatalf("rejected mutation left user %q found=%v err=%v", rejectedID, found, err)
		}
	}

	noLogin := create
	noLogin.IdempotencyKey, noLogin.User.LoginMode = "employee-no-login", identitysdk.HandlerLoginNone
	noLogin.User.User.ID, noLogin.User.User.Email, noLogin.User.User.Name = "employee-no-login", "employee-no-login@example.test", "No Login Employee"
	noLoginResult, err := handler.DeliverIdentity(t.Context(), noLogin)
	if err != nil || noLoginResult.InitialCredential != nil {
		t.Fatalf("no-login result=%+v err=%v", noLoginResult, err)
	}
	if _, found, err := core.AuthStore.GetIdentityCredential(t.Context(), cfg.IdentityWorkspaceID, "employee-no-login"); err != nil || found {
		t.Fatalf("no-login credential found=%v err=%v", found, err)
	}

	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := create
	rolledBack.IdempotencyKey = "employee-rollback"
	rolledBack.User.User.ID, rolledBack.User.User.Email, rolledBack.User.User.Name = "employee-rollback", "rollback@example.test", "Rollback"
	if _, err := handler.DeliverIdentity(identitytransaction.WithExecutor(t.Context(), tx), rolledBack); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, found, err := core.Identity.FindUser(requestcontext.WithWorkspaceID(t.Context(), cfg.IdentityWorkspaceID), "employee-rollback"); err != nil || found {
		t.Fatalf("host rollback left user found=%v err=%v", found, err)
	}
	var rollbackReceipts, rollbackAudits int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _operations WHERE workspace_id = ? AND owner = 'identity' AND kind = 'identity.handler_delivery' AND idempotency_key = ?`, cfg.IdentityWorkspaceID, rolledBack.IdempotencyKey).Scan(&rollbackReceipts); err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = ? AND record_id = ?`, cfg.IdentityWorkspaceID, "employee-rollback").Scan(&rollbackAudits); err != nil {
		t.Fatal(err)
	}
	if rollbackReceipts != 0 || rollbackAudits != 0 {
		t.Fatalf("host rollback left receipt=%d audit=%d", rollbackReceipts, rollbackAudits)
	}
	var rollbackCredentials int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _identity_credentials WHERE workspace_id = ? AND user_id = ?`, cfg.IdentityWorkspaceID, "employee-rollback").Scan(&rollbackCredentials); err != nil || rollbackCredentials != 0 {
		t.Fatalf("host rollback left credential=%d err=%v", rollbackCredentials, err)
	}

	employeeSession, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{
		WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "employee-1@example.test", Password: created.InitialCredential.InitialPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialBefore, found, err := core.AuthStore.GetIdentityCredential(t.Context(), cfg.IdentityWorkspaceID, "employee-1")
	if err != nil || !found || credentialBefore.PasswordHash == "" {
		t.Fatalf("created credential found=%v credential=%+v err=%v", found, credentialBefore, err)
	}
	update := create
	update.IdempotencyKey, update.User.Operation, update.User.LoginMode = "employee-update-1", identitysdk.HandlerUserUpdate, ""
	update.User.ExpectedVersion, update.User.User.Name = created.User.Version, "Employee One Updated"
	updated, err := handler.DeliverIdentity(t.Context(), update)
	if err != nil || updated.User.Version != created.User.Version+1 || updated.InitialCredential != nil {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	disable := create
	disable.IdempotencyKey = "employee-disable-1"
	disable.User.Operation, disable.User.ExpectedVersion = identitysdk.HandlerUserDisable, updated.User.Version
	disable.User.LoginMode = ""
	disabled, err := handler.DeliverIdentity(t.Context(), disable)
	if err != nil || disabled.User.Status != "disabled" || disabled.RevokedSessions != 1 {
		t.Fatalf("disabled=%+v err=%v", disabled, err)
	}
	if state, err := core.AuthStore.AuthSessionState(t.Context(), cfg.IdentityWorkspaceID, "employee-1", string(employeeSession.SessionID), time.Now()); err != nil || state != authrepository.AuthSessionStateRevoked {
		t.Fatalf("session state=%q err=%v", state, err)
	}
	credentialAfter, found, err := core.AuthStore.GetIdentityCredential(t.Context(), cfg.IdentityWorkspaceID, "employee-1")
	if err != nil || !found || credentialAfter.PasswordHash != credentialBefore.PasswordHash {
		t.Fatalf("update/disable changed credential found=%v before=%+v after=%+v err=%v", found, credentialBefore, credentialAfter, err)
	}

	if err := core.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	core, _ = open()
	defer core.CloseContext(t.Context())
	handler = core.Binding.(identitysdk.HandlerDeliveryBinding).HandlerDelivery()
	restartReplay, err := handler.DeliverIdentity(t.Context(), create)
	if err != nil || !restartReplay.Replayed || restartReplay.DeliveryID != created.DeliveryID || restartReplay.InitialCredential != nil {
		t.Fatalf("restart replay=%+v err=%v", restartReplay, err)
	}
	credentialAfterRestart, found, err := core.AuthStore.GetIdentityCredential(t.Context(), cfg.IdentityWorkspaceID, "employee-1")
	if err != nil || !found || credentialAfterRestart.PasswordHash != credentialBefore.PasswordHash {
		t.Fatalf("restart replay rotated credential found=%v before=%+v after=%+v err=%v", found, credentialBefore, credentialAfterRestart, err)
	}
	if _, found, err := core.AuthStore.GetIdentityCredential(t.Context(), cfg.IdentityWorkspaceID, "employee-no-login"); err != nil || found {
		t.Fatalf("restart synthesized no-login credential found=%v err=%v", found, err)
	}
}
