package moduleassembly

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityassembly "github.com/domainry/domainry-identity/internal/assembly"
	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	manifestmodel "github.com/domainry/domainry-identity/internal/domain/manifest/model"
	database "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestHandlerDeliveryModuleAcceptsRuntimeStagedProfileWithinBoundTransaction(t *testing.T) {
	_, sourceFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(projectRoot, "domainry.template.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := manifestmodel.DecodeManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Objects = append(manifest.Objects, definitionmodel.ObjectSchema{
		Key: "employee_profile", Name: "Employee profile", Description: "runtime-staged profile regression fixture",
		Fields: []definitionmodel.FieldSchema{
			{Key: "identity_user_id", Name: "Identity user", Type: "relation", Required: true, Unique: true, Validation: definitionmodel.FieldValidation{Target: "identity_user"}, Config: map[string]any{"object_key": "identity_user", "target": "identity_user", "cardinality": "one_to_one"}},
			{Key: "employment_status", Name: "Employment status", Type: "text", Required: true},
		},
	})
	manifest.IdentityProfileExtensions = append(manifest.IdentityProfileExtensions, identitymodel.IdentityProfileExtension{
		ContractVersion: identitymodel.IdentityProfileExtensionContractVersion, MinReaderVersion: identitymodel.IdentityProfileExtensionMinReaderVersion,
		ObjectKey: "employee_profile", IdentityRelationField: "identity_user_id", Cardinality: "one_to_one",
		BusinessIdentity: identitymodel.BusinessIdentityBinding{Key: "employee_profile"}, DefaultVisibility: "when_readable",
	})
	manifest.Roles = append(manifest.Roles,
		identitymodel.RoleSchema{Key: "handler_operator", Name: "Handler operator", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual, GrantableRoleKeys: []string{"employee"}, Permissions: identitymodel.RolePermissionsWithScope(identitymodel.IdentityDataScopeAll, identitycontract.IdentityHandlerDeliveryCreatePermission)},
		identitymodel.RoleSchema{Key: "employee", Name: "Employee", Audience: identitymodel.IdentityRoleAudienceAny, AssignmentMode: identitymodel.IdentityRoleAssignmentManual},
	)

	cfg := config.FromEnv()
	cfg.Environment, cfg.DatabaseDriver, cfg.DBPath = "development", "sqlite", filepath.Join(t.TempDir(), "identity.db")
	cfg.IdentityWorkspaceID, cfg.AuthAudience = "workspace-primary", "runtime-app"
	cfg.AuthJWTSecret, cfg.AuthDefaultPassword = "handler-delivery-signing-secret", "AdminPassword1!"
	store, err := database.OpenContext(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `CREATE TABLE employee_profile (id TEXT NOT NULL, workspace_id TEXT NOT NULL, identity_user_id TEXT, employment_status TEXT, PRIMARY KEY (workspace_id, id))`); err != nil {
		t.Fatal(err)
	}
	core, err := identityassembly.NewWithManifest(t.Context(), cfg, store, manifest, identityassembly.Options{WorkspaceID: cfg.IdentityWorkspaceID})
	if err != nil {
		t.Fatal(err)
	}
	defer core.CloseContext(t.Context())
	application := identitysdk.ApplicationRef{WorkspaceID: identitysdk.WorkspaceID(cfg.IdentityWorkspaceID), ApplicationKey: identitysdk.ApplicationKey(cfg.AuthAudience)}
	if _, err := core.Binding.Applications().Register(t.Context(), identitysdk.ApplicationRegistration{Application: application}); err != nil {
		t.Fatal(err)
	}
	session, err := core.Binding.Authentication().LoginWithPassword(t.Context(), identitysdk.PasswordLoginRequest{WorkspaceID: application.WorkspaceID, ApplicationKey: application.ApplicationKey, Login: "handler_operator@example.com", Password: cfg.AuthDefaultPassword})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	binding := &moduleBinding{runtime: core, application: application}
	delivery, err := binding.HandlerDeliveryUnitOfWorkBinder().BindHandlerDeliveryUnitOfWork(identitysdk.EmbeddedTransaction{Executor: tx})
	if err != nil {
		t.Fatal(err)
	}
	request := identitysdk.HandlerDeliveryRequest{
		ContractVersion: identitysdk.HandlerDeliveryContractVersionV1, AccessToken: session.AccessToken, IdempotencyKey: "employee-create-embedded",
		User:           identitysdk.HandlerUserMutation{Operation: identitysdk.HandlerUserCreate, LoginMode: identitysdk.HandlerLoginNone, User: identitysdk.User{ID: "employee-1", Name: "Employee One", Email: "employee-1@example.test", AccountType: "human", Status: "active"}},
		RoleKeys:       []string{"employee"},
		ProfileBinding: &identitysdk.HandlerProfileBindingMutation{BindingKey: "employee_profile", ObjectKey: "employee_profile", ProfileID: "profile-1", EmbeddedProfileRecord: map[string]any{"employment_status": "active"}},
	}
	result, err := delivery.DeliverIdentity(t.Context(), request)
	if err != nil {
		t.Fatalf("embedded profile delivery: %v", err)
	}
	if result.ProfileBinding == nil || result.ProfileBinding.ProfileID != "profile-1" || result.ProfileBinding.IdentityUserID != "employee-1" {
		t.Fatalf("result=%+v", result)
	}
}
