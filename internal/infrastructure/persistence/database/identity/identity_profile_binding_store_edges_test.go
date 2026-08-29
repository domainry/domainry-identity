package identity

import (
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
)

var errProfileBindingSQL = errors.New("profile binding SQL failure")

func scriptedProfileBindingStore(state *identitySQLState) (*IdentityProfileBindingStore, func()) {
	identityStore, closeDB := scriptedSQLIdentity(state)
	return NewIdentityProfileBindingStore(identityStore), closeDB
}

func validProfileBindingMutation(operation identitymodel.IdentityProfileBindingOperation) identitymodel.IdentityProfileBindingMutation {
	return identitymodel.IdentityProfileBindingMutation{
		WorkspaceID: "workspace", BindingKey: "member", ObjectKey: "member_profile", ProfileID: "profile",
		IdentityField: "identity_user_id", Operation: operation, IdempotencyKey: "key",
		RequestFingerprint: "fingerprint", ExpectedVersion: 0, ActorID: "actor",
	}
}

func TestIdentityProfileBindingStoreUnavailableAndLookupEdges(t *testing.T) {
	var nilStore *IdentityProfileBindingStore
	if _, _, err := nilStore.GetIdentityProfileBinding(t.Context(), "w", "o", "p"); err == nil {
		t.Fatal("nil binding store lookup")
	}
	if _, _, err := nilStore.GetIdentityProfileBindingByKey(t.Context(), "w", "b", "p"); err == nil {
		t.Fatal("nil binding key lookup")
	}
	if _, _, err := nilStore.GetIdentityProfileBindingReceipt(t.Context(), identitymodel.IdentityProfileBindingMutation{}); err == nil {
		t.Fatal("nil receipt lookup")
	}
	if _, err := nilStore.ExecuteIdentityProfileBindingMutation(t.Context(), identitymodel.IdentityProfileBindingMutation{}); err == nil {
		t.Fatal("nil mutation store")
	}
	emptyStore := &IdentityProfileBindingStore{}
	if _, _, err := emptyStore.GetIdentityProfileBinding(t.Context(), "w", "o", "p"); err == nil {
		t.Fatal("empty binding store lookup")
	}
	if _, _, err := emptyStore.GetIdentityProfileBindingByKey(t.Context(), "w", "b", "p"); err == nil {
		t.Fatal("empty binding key lookup")
	}
	if _, _, err := emptyStore.GetIdentityProfileBindingReceipt(t.Context(), identitymodel.IdentityProfileBindingMutation{}); err == nil {
		t.Fatal("empty receipt lookup")
	}
	if _, err := emptyStore.ExecuteIdentityProfileBindingMutation(t.Context(), identitymodel.IdentityProfileBindingMutation{}); err == nil {
		t.Fatal("empty mutation store")
	}

	bindingColumns := []string{"workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at"}
	bindingRow := []driver.Value{"workspace", "member", "member_profile", "profile", "user", "active", "", "", int64(1), "created", "updated"}
	for _, lookup := range []func(*IdentityProfileBindingStore) (identitymodel.IdentityProfileBinding, bool, error){
		func(store *IdentityProfileBindingStore) (identitymodel.IdentityProfileBinding, bool, error) {
			return store.GetIdentityProfileBinding(t.Context(), "workspace", "member_profile", "profile")
		},
		func(store *IdentityProfileBindingStore) (identitymodel.IdentityProfileBinding, bool, error) {
			return store.GetIdentityProfileBindingByKey(t.Context(), "workspace", "member", "profile")
		},
	} {
		store, closeDB := scriptedProfileBindingStore(&identitySQLState{})
		if _, found, err := lookup(store); err != nil || found {
			t.Fatalf("missing binding found=%v err=%v", found, err)
		}
		closeDB()
		store, closeDB = scriptedProfileBindingStore(&identitySQLState{queryFailAt: 1, failure: errProfileBindingSQL})
		if _, _, err := lookup(store); err == nil {
			t.Fatal("binding query failure ignored")
		}
		closeDB()
		store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{
			columns: bindingColumns, rows: [][]driver.Value{bindingRow},
		}}})
		binding, found, err := lookup(store)
		if err != nil || !found || binding.IdentityUserID != "user" {
			t.Fatalf("binding=%#v found=%v err=%v", binding, found, err)
		}
		closeDB()
	}
}

func TestIdentityRoleBindingActiveEdges(t *testing.T) {
	columns := []string{"workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at"}
	for _, row := range [][]driver.Value{
		{"workspace", "member", "member_profile", "profile", " user ", "active", "", "", int64(1), "", ""},
		{"workspace", "member", "member_profile", "profile", "other", "active", "", "", int64(1), "", ""},
		{"workspace", "member", "member_profile", "profile", "user", "unlinked", "", "", int64(1), "", ""},
	} {
		store, closeDB := scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{columns: columns, rows: [][]driver.Value{row}}}})
		active, err := store.IdentityRoleBindingActive(t.Context(), "workspace", " member ", " profile ", "user")
		want := row[4] == " user "
		if err != nil || active != want {
			t.Fatalf("active=%v want=%v err=%v", active, want, err)
		}
		closeDB()
	}
	store, closeDB := scriptedProfileBindingStore(&identitySQLState{})
	if active, err := store.IdentityRoleBindingActive(t.Context(), "workspace", "member", "profile", "user"); err != nil || active {
		t.Fatalf("missing binding active=%v err=%v", active, err)
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{queryFailAt: 1, failure: errProfileBindingSQL})
	if active, err := store.IdentityRoleBindingActive(t.Context(), "workspace", "member", "profile", "user"); err != errProfileBindingSQL || active {
		t.Fatalf("failed binding query active=%v err=%v", active, err)
	}
	closeDB()
}

func TestIdentityProfileBindingReceiptLoadEdges(t *testing.T) {
	mutation := validProfileBindingMutation(identitymodel.IdentityProfileBindingInvite)
	store, closeDB := scriptedProfileBindingStore(&identitySQLState{})
	if _, found, err := store.GetIdentityProfileBindingReceipt(t.Context(), mutation); err != nil || found {
		t.Fatalf("missing receipt found=%v err=%v", found, err)
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{queryFailAt: 1, failure: errProfileBindingSQL})
	if _, _, err := store.GetIdentityProfileBindingReceipt(t.Context(), mutation); err == nil {
		t.Fatal("receipt query failure ignored")
	}
	closeDB()
	columns := []string{"id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "idempotency_key", "request_fingerprint", "binding_json", "created_at"}
	for _, bindingJSON := range []string{"{", `{"status":"invited"}`} {
		store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{
			columns: columns,
			rows:    [][]driver.Value{{"receipt", "workspace", "member", "member_profile", "profile", "invite", "key", "fingerprint", bindingJSON, "created"}},
		}}})
		receipt, found, err := store.GetIdentityProfileBindingReceipt(t.Context(), mutation)
		if bindingJSON == "{" && err == nil {
			t.Fatal("invalid receipt JSON accepted")
		}
		if bindingJSON != "{" && (err != nil || !found || receipt.Binding.Status != identitymodel.IdentityProfileBindingInvited) {
			t.Fatalf("receipt=%#v found=%v err=%v", receipt, found, err)
		}
		closeDB()
	}
}

func TestExecuteIdentityProfileBindingMutationFailureStages(t *testing.T) {
	mutation := validProfileBindingMutation(identitymodel.IdentityProfileBindingInvite)
	store, closeDB := scriptedProfileBindingStore(&identitySQLState{})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), identitymodel.IdentityProfileBindingMutation{}); err == nil {
		t.Fatal("invalid mutation accepted")
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{beginErr: errProfileBindingSQL})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err != errProfileBindingSQL {
		t.Fatalf("begin error=%v", err)
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{queryFailAt: 1, failure: errProfileBindingSQL})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err != errProfileBindingSQL {
		t.Fatalf("receipt error=%v", err)
	}
	closeDB()

	receiptColumns := []string{"id", "workspace_id", "binding_key", "object_key", "profile_id", "operation", "idempotency_key", "request_fingerprint", "binding_json", "created_at"}
	for _, fingerprint := range []string{"other", "fingerprint"} {
		store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{
			columns: receiptColumns,
			rows:    [][]driver.Value{{"receipt", "workspace", "member", "member_profile", "profile", "invite", "key", fingerprint, `{"status":"invited"}`, "created"}},
		}}})
		receipt, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation)
		if fingerprint == "other" && apperror.CodeOf(err) != "backend.idempotency_key_reused" {
			t.Fatalf("fingerprint error=%v", err)
		}
		if fingerprint == "fingerprint" && (err != nil || !receipt.Replayed) {
			t.Fatalf("replay receipt=%#v err=%v", receipt, err)
		}
		closeDB()
	}

	baseQueries := []identitySQLQueryStep{
		{},
		{columns: []string{"identity_user_id"}, rows: [][]driver.Value{{""}}},
		{},
	}
	for failAt := 1; failAt <= 3; failAt++ {
		queries := append([]identitySQLQueryStep(nil), baseQueries...)
		store, closeDB = scriptedProfileBindingStore(&identitySQLState{
			querySteps: queries, execFailAt: failAt, failure: errProfileBindingSQL,
		})
		if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err == nil {
			t.Fatalf("write failure %d ignored", failAt)
		}
		closeDB()
	}
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: append([]identitySQLQueryStep(nil), baseQueries...), commitErr: errProfileBindingSQL})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err == nil {
		t.Fatal("commit failure ignored")
	}
	closeDB()
}

func TestIdentityProfileBindingMutationLoadAndVersionEdges(t *testing.T) {
	mutation := validProfileBindingMutation(identitymodel.IdentityProfileBindingClaim)
	mutation.IdentityUserID = "user"
	store, closeDB := scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{}, {}}})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); apperror.CodeOf(err) != "backend.identity.profile_not_found" {
		t.Fatalf("missing profile error=%v", err)
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{queryFailAt: 2, failure: errProfileBindingSQL, querySteps: []identitySQLQueryStep{{}}})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err != errProfileBindingSQL {
		t.Fatalf("profile query error=%v", err)
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{
		queryFailAt: 3, failure: errProfileBindingSQL,
		querySteps: []identitySQLQueryStep{{}, {columns: []string{"identity_user_id"}, rows: [][]driver.Value{{""}}}},
	})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err != errProfileBindingSQL {
		t.Fatalf("binding query error=%v", err)
	}
	closeDB()

	bindingColumns := []string{"workspace_id", "binding_key", "object_key", "profile_id", "identity_user_id", "status", "invitation_channel", "claim_proof_type", "version", "created_at", "updated_at"}
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{
		{}, {columns: []string{"identity_user_id"}, rows: [][]driver.Value{{""}}},
		{columns: bindingColumns, rows: [][]driver.Value{{"workspace", "member", "member_profile", "profile", "", "invited", "", "", int64(2), "created", "updated"}}},
	}})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); apperror.CodeOf(err) != "backend.identity.profile_binding_version_conflict" {
		t.Fatalf("version error=%v", err)
	}
	closeDB()

	mutation.SystemManagedRoleIDs = []string{"member-role"}
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{
		querySteps: []identitySQLQueryStep{
			{}, {columns: []string{"identity_user_id"}, rows: [][]driver.Value{{""}}}, {},
		},
		execFailAt: 3, failure: errProfileBindingSQL,
	})
	if _, err := store.ExecuteIdentityProfileBindingMutation(t.Context(), mutation); err == nil {
		t.Fatal("system-managed role synchronization failure ignored")
	}
	closeDB()
}

func TestIdentityProfileBindingTransitionAndValidationEdges(t *testing.T) {
	for _, test := range []struct {
		mutation identitymodel.IdentityProfileBindingMutation
		current  string
		code     string
	}{
		{validProfileBindingMutation(identitymodel.IdentityProfileBindingInvite), "user", "backend.identity.profile_already_bound"},
		{validProfileBindingMutation(identitymodel.IdentityProfileBindingClaim), "", "backend.identity.profile_binding_target_invalid"},
		{validProfileBindingMutation(identitymodel.IdentityProfileBindingBind), "user", "backend.identity.profile_already_bound"},
		{validProfileBindingMutation(identitymodel.IdentityProfileBindingRebind), "", "backend.identity.profile_rebind_invalid"},
		{func() identitymodel.IdentityProfileBindingMutation {
			m := validProfileBindingMutation(identitymodel.IdentityProfileBindingRebind)
			m.IdentityUserID, m.Reason = "user", "reason"
			return m
		}(), "user", "backend.identity.profile_binding_unchanged"},
		{validProfileBindingMutation(identitymodel.IdentityProfileBindingUnlink), "", "backend.identity.profile_not_bound"},
		{validProfileBindingMutation(identitymodel.IdentityProfileBindingOperation("other")), "", "backend.identity.profile_binding_operation_invalid"},
	} {
		if _, _, err := identityProfileBindingTransition(test.mutation, test.current); apperror.CodeOf(err) != test.code {
			t.Fatalf("transition code=%q error=%v", test.code, err)
		}
	}
	rebind := validProfileBindingMutation(identitymodel.IdentityProfileBindingRebind)
	rebind.IdentityUserID, rebind.Reason = "next", "reason"
	if status, user, err := identityProfileBindingTransition(rebind, "current"); err != nil || status != identitymodel.IdentityProfileBindingActive || user != "next" {
		t.Fatalf("rebind transition status=%q user=%q err=%v", status, user, err)
	}
	rebind.IdentityUserID = ""
	if _, _, err := identityProfileBindingTransition(rebind, "current"); apperror.CodeOf(err) != "backend.identity.profile_rebind_invalid" {
		t.Fatalf("empty rebind user error=%v", err)
	}
	rebind.IdentityUserID, rebind.Reason = "next", ""
	if _, _, err := identityProfileBindingTransition(rebind, "current"); apperror.CodeOf(err) != "backend.identity.profile_rebind_invalid" {
		t.Fatalf("empty rebind reason error=%v", err)
	}

	base := validProfileBindingMutation(identitymodel.IdentityProfileBindingInvite)
	invalid := []identitymodel.IdentityProfileBindingMutation{
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.WorkspaceID = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.BindingKey = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.ObjectKey = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.ProfileID = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.IdentityField = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.IdempotencyKey = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.RequestFingerprint = ""; return m }(),
		func() identitymodel.IdentityProfileBindingMutation { m := base; m.ExpectedVersion = -1; return m }(),
	}
	for _, mutation := range invalid {
		if err := validateIdentityProfileBindingMutation(mutation); err == nil {
			t.Fatalf("invalid mutation accepted: %#v", mutation)
		}
	}
}

func TestIdentityProfileBindingWriteAndEventFailureHelpers(t *testing.T) {
	mutation := validProfileBindingMutation(identitymodel.IdentityProfileBindingRebind)
	mutation.SystemManagedRoleIDs = []string{" role ", "", "role", "other"}
	for _, operation := range []identitymodel.IdentityProfileBindingOperation{
		identitymodel.IdentityProfileBindingInvite,
		identitymodel.IdentityProfileBindingBind,
	} {
		noWriteMutation := mutation
		noWriteMutation.Operation = operation
		store, closeDB := scriptedProfileBindingStore(&identitySQLState{})
		tx, err := store.store.DB().BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = store.synchronizeSystemManagedRoles(t.Context(), tx, noWriteMutation, "previous", "", "now")
		_ = tx.Rollback()
		closeDB()
		if err != nil {
			t.Fatalf("no-write managed role operation %q failed: %v", operation, err)
		}
	}
	for failAt := 1; failAt <= 3; failAt++ {
		state := &identitySQLState{execFailAt: failAt, failure: errProfileBindingSQL}
		store, closeDB := scriptedProfileBindingStore(state)
		tx, err := store.store.DB().BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = store.synchronizeSystemManagedRoles(t.Context(), tx, mutation, "previous", "next", "now")
		_ = tx.Rollback()
		closeDB()
		if err == nil {
			t.Fatalf("managed role write failure %d ignored", failAt)
		}
	}
	store, closeDB := scriptedProfileBindingStore(&identitySQLState{queryFailAt: 1, failure: errProfileBindingSQL})
	if _, err := store.ListIdentityProfileBindingEvents(t.Context(), "workspace", "object", "profile"); err == nil {
		t.Fatal("event query failure ignored")
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"only"}, rows: [][]driver.Value{{"value"}},
	}}})
	if _, err := store.ListIdentityProfileBindingEvents(t.Context(), "workspace", "object", "profile"); err == nil {
		t.Fatal("event scan failure ignored")
	}
	closeDB()
	store, closeDB = scriptedProfileBindingStore(&identitySQLState{querySteps: []identitySQLQueryStep{{
		columns: []string{"id"}, nextErr: errProfileBindingSQL,
	}}})
	if _, err := store.ListIdentityProfileBindingEvents(t.Context(), "workspace", "object", "profile"); err == nil {
		t.Fatal("event iteration failure ignored")
	}
	closeDB()
}

func TestNormalizeProfileBindingWriteErrorEdges(t *testing.T) {
	if normalizeProfileBindingWriteError(nil) != nil {
		t.Fatal("nil write error changed")
	}
	unique := errors.New("UNIQUE constraint")
	if apperror.CodeOf(normalizeProfileBindingWriteError(unique)) != "backend.identity.profile_binding_conflict" {
		t.Fatal("unique conflict not normalized")
	}
	duplicate := errors.New("duplicate key")
	if apperror.CodeOf(normalizeProfileBindingWriteError(duplicate)) != "backend.identity.profile_binding_conflict" {
		t.Fatal("duplicate conflict not normalized")
	}
	plain := errors.New("disk failure")
	if normalizeProfileBindingWriteError(plain) != plain {
		t.Fatal("plain write error changed")
	}
}

func TestIdentityProfileBindingUpdateRowsAffectedEdges(t *testing.T) {
	mutation := validProfileBindingMutation(identitymodel.IdentityProfileBindingClaim)
	for _, state := range []*identitySQLState{
		{execFailAt: 1, failure: errProfileBindingSQL},
		{rowsFailAt: 1, failure: errProfileBindingSQL},
		{rowsZeroAt: 1},
	} {
		store, closeDB := scriptedProfileBindingStore(state)
		tx, err := store.store.DB().BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		err = store.updateProfileIdentityUser(t.Context(), tx, mutation, "", "user", "now")
		_ = tx.Rollback()
		closeDB()
		if err == nil {
			t.Fatal("profile update failure ignored")
		}
	}
}
