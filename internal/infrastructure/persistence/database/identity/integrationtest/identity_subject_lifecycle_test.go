package identity_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	authpersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/auth"
	"path/filepath"
	"strings"
	"testing"
	"time"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	. "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func bindSharedSubjectLifecycle(t *testing.T, db *sql.DB, store *identitypersistence.SQLIdentityStore) {
	t.Helper()
	store.BindSubjectLifecyclePersistence()
}

func beginSharedSubjectErasure(t *testing.T, db *sql.DB, workspaceID, subjectID, requestID string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), `INSERT INTO _subject_requests(id,workspace_id,request_type,kind,status,subject_id,resolved_identity,updated_at,payload_json) VALUES(?,?,'subject_request','erase','executing',?,?,?,'{}')`, requestID, workspaceID, subjectID, subjectID, time.Now().UTC().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO _subject_steps(workspace_id,request_id,owner,operation,payload_json,completed_at) VALUES(?,?,'lifecycle','erase_fence','{}',?)`, workspaceID, requestID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func TestIdentitySubjectLifecycleContract(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-lifecycle.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	user := identitymodel.IdentityUser{
		ID: "user", Name: "Dr. User Example", GivenName: "User", MiddleName: "Middle", FamilyName: "Example",
		NamePrefix: "Dr.", NameSuffix: "PhD", NativeName: "用户", NameLocale: "en-US",
		Email: "user@example.com", Phone: "1", OrgID: "organization-unit", SupportOrgID: "supported-organization-unit", WorkerNo: "E-1",
		WorkerType: identitymodel.IdentityWorkerEmployee, WorkStatus: identitymodel.IdentityWorkActive,
	}
	if err := identity.UpsertIdentityUser(t.Context(), "workspace-primary", user); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), "INSERT INTO _identity_credentials (user_id, workspace_id, password_hash, password_updated_at, failed_login_count, must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", "user", "workspace-primary", "hash", "now", 0, false, "now", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), "INSERT INTO _identity_mfa_factors (id, workspace_id, user_id, factor_type, status, verified_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", "factor", "workspace-primary", "user", "totp", "active", "now", "now", "now"); err != nil {
		t.Fatal(err)
	}
	if err := identity.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{
		UserID: "user", RoleID: "employee", Source: "manual", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(t.Context(), `INSERT INTO _identity_profile_bindings
		(id,workspace_id,binding_key,object_key,profile_id,identity_user_id,status,version,created_at,updated_at)
		VALUES ('binding','workspace-primary','member','member_profile','member-1','user','active',1,1,1)`); err != nil {
		t.Fatal(err)
	}

	lifecycle := identitypersistence.NewIdentitySubjectLifecycleStore(identity, authpersistence.NewAuthStore(identity).EraseSubjectLoginArtifacts)
	if lifecycle.Owner(t.Context()) != "identity" {
		t.Fatal("owner mismatch")
	}
	if _, err := lifecycle.ResolveSubject(t.Context(), "workspace-primary", "record", "user"); err == nil {
		t.Fatal("unsupported type accepted")
	}
	if _, err := lifecycle.ResolveSubject(t.Context(), "workspace-primary", "user", "missing"); err == nil {
		t.Fatal("missing subject resolved")
	}
	if id, err := lifecycle.ResolveSubject(t.Context(), "workspace-primary", "user", "user@example.com"); err != nil || id != "user" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if _, err := lifecycle.EraseSubject(t.Context(), "workspace-primary", "user", nil); err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("unbound shared Lifecycle persistence error=%v", err)
	}
	bindSharedSubjectLifecycle(t, store.DB(), identity)
	beginSharedSubjectErasure(t, store.DB(), "workspace-primary", "user", "subject:user")
	preview, err := lifecycle.PreviewSubject(t.Context(), "workspace-primary", "user")
	if err != nil || !strings.Contains(string(preview), `"credentials":1`) || !strings.Contains(string(preview), `"mfa_factors":1`) {
		t.Fatalf("preview=%s err=%v", preview, err)
	}
	exported, err := lifecycle.ExportSubject(t.Context(), "workspace-primary", "user")
	if err != nil || !strings.Contains(string(exported), `"email":"user@example.com"`) ||
		!strings.Contains(string(exported), `"family_name":"Example"`) || !strings.Contains(string(exported), `"native_name":"用户"`) ||
		!strings.Contains(string(exported), `"worker_no":"E-1"`) ||
		!strings.Contains(string(exported), `"org_id":"organization-unit"`) ||
		!strings.Contains(string(exported), `"support_org_id":"supported-organization-unit"`) ||
		!strings.Contains(string(exported), `"role_assignments":[{"`) ||
		!strings.Contains(string(exported), `"profile_relations":[{"`) ||
		!strings.Contains(string(exported), `"object_key":"member_profile"`) {
		t.Fatalf("export=%s err=%v", exported, err)
	}
	erased, err := lifecycle.EraseSubject(t.Context(), "workspace-primary", "user", nil)
	if err != nil || !strings.Contains(string(erased), `"anonymized":1`) {
		t.Fatalf("erase=%s err=%v", erased, err)
	}
	loaded, found, err := identity.GetIdentityUser(t.Context(), "workspace-primary", "user")
	if err != nil || !found || loaded.Status != "erased" || loaded.Email == user.Email ||
		loaded.GivenName != "" || loaded.MiddleName != "" || loaded.FamilyName != "" || loaded.NamePrefix != "" ||
		loaded.NameSuffix != "" || loaded.NativeName != "" || loaded.NameLocale != "" || loaded.SupportOrgID != "" {
		t.Fatalf("loaded=%#v found=%v err=%v", loaded, found, err)
	}
	var legacyTableCount int
	if err := store.DB().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_identity_subject_erasure_receipts'`).Scan(&legacyTableCount); err != nil || legacyTableCount != 0 {
		t.Fatalf("legacy Identity erasure receipt table count=%d err=%v", legacyTableCount, err)
	}
	var factorCount int
	if err := store.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM _identity_mfa_factors WHERE workspace_id = ? AND user_id = ?", "workspace-primary", "user").Scan(&factorCount); err != nil || factorCount != 0 {
		t.Fatalf("MFA factors retained: count=%d err=%v", factorCount, err)
	}
	if _, err := lifecycle.EraseSubject(t.Context(), "workspace-primary", "missing", nil); err == nil {
		t.Fatal("missing erase succeeded")
	}
	// Ordinary management must never turn the erased marker into a disabled or
	// absent row: either would allow the stable account ID to be reused.
	marker := loaded
	for name, mutate := range map[string]func(){
		"activate": func() {
			_ = identity.SetIdentityUserStatus(t.Context(), "workspace-primary", "user", identitymodel.IdentityStatusActive)
		},
		"scoped activate": func() {
			_, _ = identity.SetIdentityUserStatusWithinDataScope(t.Context(), "workspace-primary", "user", identitymodel.IdentityStatusActive, identitymodel.IdentityDataScopeFilter{Unrestricted: true})
		},
		"disable": func() {
			_, _, _ = identity.DisableIdentityAccountWithinDataScope(t.Context(), "workspace-primary", "user", identitymodel.IdentityDataScopeFilter{Unrestricted: true})
		},
		"delete": func() { _ = identity.RemoveIdentityUser(t.Context(), "workspace-primary", "user") },
		"scoped delete": func() {
			_, _ = identity.RemoveIdentityUserWithinDataScope(t.Context(), "workspace-primary", "user", identitymodel.IdentityDataScopeFilter{Unrestricted: true})
		},
		"restore PII": func() { _ = identity.UpsertIdentityUser(t.Context(), "workspace-primary", user) },
	} {
		t.Run(name, func(t *testing.T) {
			mutate()
			after, found, err := identity.GetIdentityUser(t.Context(), "workspace-primary", "user")
			if err != nil || !found || after != marker {
				t.Fatalf("erased marker changed: %+v err=%v", after, err)
			}
		})
	}
	if err := identity.CreateIdentityUser(t.Context(), "workspace-primary", user); err == nil {
		t.Fatal("erased account ID reused")
	}

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := lifecycle.ResolveSubject(cancelled, "workspace-primary", "user", "user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolve cancel=%v", err)
	}
	if _, err := lifecycle.PreviewSubject(cancelled, "workspace-primary", "user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("preview cancel=%v", err)
	}
	if _, err := lifecycle.ExportSubject(cancelled, "workspace-primary", "user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("export cancel=%v", err)
	}
	if _, err := lifecycle.EraseSubject(cancelled, "workspace-primary", "user", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("erase cancel=%v", err)
	}
}

func TestIdentitySubjectEraseRollsBackAtEveryOwnedFactStage(t *testing.T) {
	stages := []struct {
		name, table, operation string
	}{
		{"refresh tokens", "_identity_auth_refresh_tokens", "DELETE"},
		{"credentials", "_identity_credentials", "DELETE"},
		{"external accounts", "_identity_external_accounts", "DELETE"},
		{"mfa factors", "_identity_mfa_factors", "DELETE"},
		{"role assignments", "_identity_user_role_assignments", "DELETE"},
		{"identity anonymization", "_identity_users", "UPDATE"},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-erase-rollback.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.EnsureSchema(t.Context()); err != nil {
				t.Fatal(err)
			}
			identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
			if err != nil {
				t.Fatal(err)
			}
			if err := identity.UpsertIdentityUser(t.Context(), "workspace-primary", identitymodel.IdentityUser{
				ID: "user", Name: "Original Name", Email: "original@example.test", Phone: "100", Status: identitymodel.IdentityStatusActive,
			}); err != nil {
				t.Fatal(err)
			}
			if err := identity.AssignIdentityUserRole(t.Context(), "workspace-primary", identitymodel.IdentityUserRoleAssignment{
				UserID: "user", RoleID: "role",
			}); err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{
				`INSERT INTO _identity_credentials
					(user_id, workspace_id, password_hash, password_updated_at, failed_login_count, must_change_password, created_at, updated_at)
					VALUES ('user','workspace-primary','hash',1,0,0,1,1)`,
				`INSERT INTO _identity_external_accounts
					(id, workspace_id, user_id, provider, provider_subject, email, phone, display_name, avatar_url, metadata, linked_at, created_at, updated_at)
					VALUES ('external','workspace-primary','user','oidc','subject','original@example.test','100','Original','','{}',1,1,1)`,
				`INSERT INTO _identity_mfa_factors
					(id, workspace_id, user_id, factor_type, status, verified_at, created_at, updated_at)
					VALUES ('factor','workspace-primary','user','totp','active',1,1,1)`,
				`INSERT INTO _identity_auth_refresh_tokens
					(id, workspace_id, user_id, session_id, token_hash, expires_at, created_at, updated_at)
					VALUES ('token','workspace-primary','user','session','hash',32503680000000,1,1)`,
			} {
				if _, err := store.DB().ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
			}
			trigger := "CREATE TRIGGER fail_erase_stage BEFORE " + stage.operation + " ON " + stage.table +
				" BEGIN SELECT RAISE(ABORT, 'injected erase failure'); END"
			if _, err := store.DB().ExecContext(t.Context(), trigger); err != nil {
				t.Fatal(err)
			}
			lifecycle := identitypersistence.NewIdentitySubjectLifecycleStore(identity, authpersistence.NewAuthStore(identity).EraseSubjectLoginArtifacts)
			bindSharedSubjectLifecycle(t, store.DB(), identity)
			beginSharedSubjectErasure(t, store.DB(), "workspace-primary", "user", "subject:user")
			if _, err := lifecycle.EraseSubject(t.Context(), "workspace-primary", "user", nil); err == nil {
				t.Fatal("injected erase failure was ignored")
			}
			for _, table := range []string{
				"_identity_credentials", "_identity_external_accounts", "_identity_mfa_factors",
				"_identity_auth_refresh_tokens", "_identity_user_role_assignments",
			} {
				var count int
				if err := store.DB().QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE workspace_id='workspace-primary' AND user_id='user'").Scan(&count); err != nil || count != 1 {
					t.Fatalf("table=%s count=%d err=%v", table, count, err)
				}
			}
			var name, email, phone, status string
			if err := store.DB().QueryRowContext(t.Context(), `SELECT name,email,phone,status FROM _identity_users
				WHERE workspace_id='workspace-primary' AND id='user'`).Scan(&name, &email, &phone, &status); err != nil {
				t.Fatal(err)
			}
			if name != "Original Name" || email != "original@example.test" || phone != "100" || status != string(identitymodel.IdentityStatusActive) {
				t.Fatalf("identity partially anonymized: name=%q email=%q phone=%q status=%q", name, email, phone, status)
			}
		})
	}
}

func TestIdentityExportHelpers(t *testing.T) {
	store, err := OpenContext(t.Context(), config.Config{DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-exports.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine(), " schema ")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DB() == nil || identity.SQLRenderer().Identifier("id") == "" || identitypersistence.NowString() == "" {
		t.Fatal("empty SQL helper")
	}
	if identitypersistence.ValueFromNull(sql.NullString{}) != "" || identitypersistence.ValueFromNull(sql.NullString{String: "x", Valid: true}) != "x" {
		t.Fatal("null conversion")
	}
	values := []driver.Value{"id", "user", "session", "audience", int64(1000), `["pwd"]`, "urn:domainry:acr:1", "hash", time.Now().UnixMilli(), int64(0), nil, int64(0), int64(1)}
	token, err := identitypersistence.ScanAuthRefreshToken(identityTestScanner{values: values})
	if err != nil || token.ID != "id" || token.RevokedAt != "" {
		t.Fatalf("token=%#v err=%v", token, err)
	}
	if _, err := identitypersistence.ScanAuthRefreshToken(identityTestScanner{err: errors.New("scan")}); err == nil {
		t.Fatal("scan error ignored")
	}
	if !json.Valid(json.RawMessage(`{}`)) {
		t.Fatal("json sanity")
	}
}

type identityTestScanner struct {
	values []driver.Value
	err    error
}

func (s identityTestScanner) Scan(dest ...any) error {
	if s.err != nil {
		return s.err
	}
	for index, value := range s.values {
		switch target := dest[index].(type) {
		case *string:
			*target = value.(string)
		case *int64:
			*target = value.(int64)
		case *sql.NullString:
			if value != nil {
				target.String, target.Valid = value.(string), true
			}
		default:
			return errors.New("unsupported scan target")
		}
	}
	return nil
}
