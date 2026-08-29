package identity_test

import (
	"path/filepath"
	"reflect"
	"testing"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	persistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
	"github.com/domainry/domainry-identity/internal/platform/config"
)

func TestIdentityUserGlobalNameFieldsRoundTripAndRemainSearchable(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-global-name.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if err := identityStore.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	store, err := identitypersistence.NewSQLIdentityStore(t.Context(), identityStore.DB(), identityStore.PersistenceDialect(), identityStore.DatabaseSchema())
	if err != nil {
		t.Fatal(err)
	}
	want := identitymodel.IdentityUser{
		ID: "global-name", Name: "Dr. María José Carreño Quiñones",
		GivenName: "María", MiddleName: "José", FamilyName: "Carreño Quiñones",
		NamePrefix: "Dr.", NameSuffix: "PhD", NativeName: "마리아 카레뇨", NameLocale: "es-CO",
		Email: "maria@example.com", Phone: "+1-555-0100", Status: identitymodel.IdentityStatusActive,
	}
	if err := store.UpsertIdentityUser(t.Context(), "default", want); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.GetIdentityUser(t.Context(), "default", want.ID)
	expected := want
	expected.AccountType = identitymodel.IdentityAccountHuman
	expected.Version = 1
	expected.CreatedAt = got.CreatedAt
	expected.UpdatedAt = got.UpdatedAt
	if err != nil || !found || got.CreatedAt == "" || got.UpdatedAt == "" || !reflect.DeepEqual(got, expected) {
		t.Fatalf("global name round trip got=%#v found=%v err=%v want=%#v", got, found, err, expected)
	}
	for field, search := range map[string]string{"family_name": "Quiñones", "native_name": "카레뇨", "given_name": "María"} {
		page, searchErr := store.SearchIdentityUsers(t.Context(), "default", identitymodel.IdentityListQuery{
			PageSize: 20, Search: search, SearchFields: []string{field},
			Sort: []identitymodel.IdentitySortRule{{Field: "id", Direction: "asc"}},
		})
		if searchErr != nil || page.Total != 1 || page.Items[0].ID != want.ID {
			t.Fatalf("search %s=%q page=%#v err=%v", field, search, page, searchErr)
		}
	}
}

func TestEnsureIdentitySchemaAddsGlobalNameColumnsWithoutChangingLegacyDisplayName(t *testing.T) {
	identityStore, err := persistence.OpenContext(t.Context(), config.Config{
		DatabaseDriver: "sqlite", DBPath: filepath.Join(t.TempDir(), "identity-global-name-upgrade.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = identityStore.Close() })
	if _, err := identityStore.DB().Exec(`CREATE TABLE identity_users (
		id TEXT PRIMARY KEY,
		workspace_id TEXT NOT NULL,
		name TEXT NOT NULL,
		email TEXT NOT NULL,
		phone TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	INSERT INTO identity_users (id, workspace_id, name, email, phone, status, created_at, updated_at)
	VALUES ('legacy-user', 'default', '单名', 'legacy@example.com', '', 'active', 'before', 'before');`); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.EnsureIdentitySchema(t.Context()); err != nil {
		t.Fatalf("global name schema upgrade is not idempotent: %v", err)
	}
	var name, given, middle, family, prefix, suffix, native, locale string
	if err := identityStore.DB().QueryRow(`SELECT name, given_name, middle_name, family_name, name_prefix, name_suffix, native_name, name_locale
		FROM identity_users WHERE workspace_id = 'default' AND id = 'legacy-user'`).
		Scan(&name, &given, &middle, &family, &prefix, &suffix, &native, &locale); err != nil {
		t.Fatal(err)
	}
	if name != "单名" || given != "" || middle != "" || family != "" || prefix != "" || suffix != "" || native != "" || locale != "" {
		t.Fatalf("legacy display name changed during upgrade: name=%q structured=%q/%q/%q/%q/%q/%q/%q", name, given, middle, family, prefix, suffix, native, locale)
	}
}
