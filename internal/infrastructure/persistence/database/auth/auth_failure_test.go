package auth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/idempotency"
	authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	identitypersistence "github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/identity"
)

func TestAuthMutationStagedFailures(t *testing.T) {
	base := authFailureBase(t)
	wantErr := errors.New("injected auth mutation failure")
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	request := authmodel.AuthMutationClaimRequest{Receipt: authmodel.AuthMutationReceipt{WorkspaceID: "workspace-primary", UseCase: "reset", TargetID: "user", IdempotencyKey: "key"}, RequestFingerprint: "fp", LeaseOwner: "worker", Now: now, LeaseTTL: time.Second}
	expired := authMutationQueryStep{columns: authMutationReceiptColumns(), rows: [][]driver.Value{authMutationRow("processing", "fp", now.Add(-time.Second), 1)}}
	live := authMutationQueryStep{columns: authMutationReceiptColumns(), rows: [][]driver.Value{authMutationRow("processing", "fp", now.Add(time.Minute), 2)}}

	for _, test := range []struct {
		name  string
		state *authDBState
	}{
		{name: "find", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}, querySteps: []authMutationQueryStep{{err: wantErr}}}},
		{name: "missing after constraint", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}, querySteps: []authMutationQueryStep{{columns: authMutationReceiptColumns()}}}},
		{name: "reclaim exec", state: &authDBState{execSteps: []authExecStep{{err: wantErr}, {err: wantErr}}, querySteps: []authMutationQueryStep{expired}}},
		{name: "reclaim rows", state: &authDBState{execSteps: []authExecStep{{err: wantErr}, {rowsErr: wantErr}}, querySteps: []authMutationQueryStep{expired}}},
		{name: "reload", state: &authDBState{execSteps: []authExecStep{{err: wantErr}, {rows: 1}}, querySteps: []authMutationQueryStep{expired, {err: wantErr}}}},
		{name: "reload missing", state: &authDBState{execSteps: []authExecStep{{err: wantErr}, {rows: 1}}, querySteps: []authMutationQueryStep{expired, {columns: authMutationReceiptColumns()}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, closeDB := scriptedAuthStore(base, test.state)
			defer closeDB()
			if _, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", request); err == nil {
				t.Fatal("claim failure ignored")
			}
		})
	}
	repository, closeDB := scriptedAuthStore(base, &authDBState{execSteps: []authExecStep{{err: wantErr}, {rows: 0}}, querySteps: []authMutationQueryStep{expired, live}})
	result, err := repository.TryBeginAuthMutation(t.Context(), "workspace-primary", request)
	closeDB()
	if err != nil || result.Decision != idempotency.DecisionInProgress {
		t.Fatalf("race result=%#v err=%v", result, err)
	}

	completion := authmodel.AuthMutationCompletion{ReceiptID: "receipt", LeaseOwner: "worker", FencingToken: 1, Result: true}
	for _, step := range []authExecStep{{err: wantErr}, {rowsErr: wantErr}} {
		repository, closeDB := scriptedAuthStore(base, &authDBState{execSteps: []authExecStep{step}})
		_, err := repository.CompleteAuthMutation(t.Context(), "workspace-primary", completion)
		closeDB()
		if err == nil {
			t.Fatal("completion failure ignored")
		}
	}
	repository, closeDB = scriptedAuthStore(base, &authDBState{execSteps: []authExecStep{{rows: 0}}, querySteps: []authMutationQueryStep{{err: wantErr}}})
	_, err = repository.CompleteAuthMutation(t.Context(), "workspace-primary", completion)
	closeDB()
	if err == nil {
		t.Fatal("lease-lost lookup failure ignored")
	}
}

func TestAuthStoreTransactionAndRowsFailures(t *testing.T) {
	base := authFailureBase(t)
	wantErr := errors.New("injected auth store failure")
	credential := identitymodel.IdentityCredential{UserID: "user", PasswordHash: "hash"}
	account := identitymodel.IdentityExternalAccount{ID: "account", UserID: "user", Provider: "oidc", ProviderSubject: "subject"}
	factor := identitymodel.IdentityMFAFactor{ID: "factor", UserID: "user", Type: "totp", Status: "active", VerifiedAt: "now"}

	for _, test := range []struct {
		name  string
		state *authDBState
		call  func(AuthStore) error
	}{
		{name: "credential upsert", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}}, call: func(s AuthStore) error {
			return s.UpsertIdentityCredential(t.Context(), "workspace-primary", credential)
		}},
		{name: "external upsert", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}}, call: func(s AuthStore) error {
			return s.UpsertIdentityExternalAccount(t.Context(), "workspace-primary", account)
		}},
		{name: "MFA upsert", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}}, call: func(s AuthStore) error { return s.UpsertIdentityMFAFactor(t.Context(), "workspace-primary", factor) }},
		{name: "MFA revoke exec", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}}, call: func(s AuthStore) error {
			return s.RevokeIdentityMFAFactor(t.Context(), "workspace-primary", "user", "factor")
		}},
		{name: "MFA revoke rows", state: &authDBState{execSteps: []authExecStep{{rowsErr: wantErr}}}, call: func(s AuthStore) error {
			return s.RevokeIdentityMFAFactor(t.Context(), "workspace-primary", "user", "factor")
		}},
		{name: "MFA revoke missing", state: &authDBState{execSteps: []authExecStep{{rows: 0}}}, call: func(s AuthStore) error {
			return s.RevokeIdentityMFAFactor(t.Context(), "workspace-primary", "user", "factor")
		}},
		{name: "revoke list exec", state: &authDBState{execSteps: []authExecStep{{err: wantErr}}}, call: func(s AuthStore) error {
			_, err := s.RevokeAuthRefreshTokensForUser(t.Context(), "workspace-primary", "user", "now")
			return err
		}},
		{name: "revoke list rows", state: &authDBState{execSteps: []authExecStep{{rowsErr: wantErr}}}, call: func(s AuthStore) error {
			_, err := s.RevokeAuthRefreshTokensForUser(t.Context(), "workspace-primary", "user", "now")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, closeDB := scriptedAuthStore(base, test.state)
			defer closeDB()
			if err := test.call(repository); err == nil {
				t.Fatal("stage failure ignored")
			}
		})
	}

	refreshColumns := []string{"id", "user_id", "session_id", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "last_used_at", "created_at"}
	externalColumns := []string{"id", "user_id", "provider", "provider_subject", "email", "phone", "display_name", "avatar_url", "metadata", "linked_at"}
	mfaColumns := []string{"id", "user_id", "factor_type", "label", "provider", "provider_ref", "status", "verified_at", "last_used_at", "created_at", "updated_at"}
	for _, test := range []struct {
		name string
		step authMutationQueryStep
		call func(AuthStore) error
	}{
		{name: "refresh query", step: authMutationQueryStep{err: wantErr}, call: func(s AuthStore) error {
			_, err := s.ListAuthRefreshTokensForUser(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "refresh scan", step: authMutationQueryStep{columns: append(refreshColumns, "extra"), rows: [][]driver.Value{{"id", "user", "session", "hash", "expires", nil, nil, nil, "created", "extra"}}}, call: func(s AuthStore) error {
			_, err := s.ListAuthRefreshTokensForUser(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "refresh rows", step: authMutationQueryStep{columns: refreshColumns, nextErr: wantErr}, call: func(s AuthStore) error {
			_, err := s.ListAuthRefreshTokensForUser(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "external query", step: authMutationQueryStep{err: wantErr}, call: func(s AuthStore) error {
			_, err := s.ListIdentityExternalAccounts(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "external scan", step: authMutationQueryStep{columns: append(externalColumns, "extra"), rows: [][]driver.Value{{"id", "user", "oidc", "subject", nil, nil, nil, nil, nil, "linked", "extra"}}}, call: func(s AuthStore) error {
			_, err := s.ListIdentityExternalAccounts(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "external rows", step: authMutationQueryStep{columns: externalColumns, nextErr: wantErr}, call: func(s AuthStore) error {
			_, err := s.ListIdentityExternalAccounts(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "MFA query", step: authMutationQueryStep{err: wantErr}, call: func(s AuthStore) error {
			_, err := s.ListIdentityMFAFactors(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "MFA scan", step: authMutationQueryStep{columns: append(mfaColumns, "extra"), rows: [][]driver.Value{{"id", "user", "totp", nil, nil, nil, "active", nil, nil, "created", "updated", "extra"}}}, call: func(s AuthStore) error {
			_, err := s.ListIdentityMFAFactors(t.Context(), "workspace-primary", "user")
			return err
		}},
		{name: "MFA rows", step: authMutationQueryStep{columns: mfaColumns, nextErr: wantErr}, call: func(s AuthStore) error {
			_, err := s.ListIdentityMFAFactors(t.Context(), "workspace-primary", "user")
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, closeDB := scriptedAuthStore(base, &authDBState{querySteps: []authMutationQueryStep{test.step}})
			defer closeDB()
			if err := test.call(repository); err == nil {
				t.Fatal("query failure ignored")
			}
		})
	}
}

func TestAuthProjectionSecurityFactsAndMFAValidationEdges(t *testing.T) {
	base := authFailureBase(t)
	wantErr := errors.New("injected projection security failure")
	if facts, err := base.ListUserProjectionSecurityFacts(t.Context(), "", []string{"user"}); err == nil || len(facts) != 0 {
		t.Fatalf("invalid workspace facts=%v err=%v", facts, err)
	}
	if facts, err := base.ListUserProjectionSecurityFacts(t.Context(), "workspace-primary", nil); err != nil || len(facts) != 0 {
		t.Fatalf("empty users facts=%v err=%v", facts, err)
	}
	columns := []string{"user_id", "locked_until", "last_login_at", "active_sessions", "mfa_enabled"}
	steps := []authMutationQueryStep{
		{err: wantErr},
		{columns: append(columns, "extra"), rows: [][]driver.Value{{"user", "", "", int64(1), true, "extra"}}},
		{columns: columns, nextErr: wantErr},
	}
	for index, step := range steps {
		repository, closeDB := scriptedAuthStore(base, &authDBState{querySteps: []authMutationQueryStep{step}})
		_, err := repository.ListUserProjectionSecurityFacts(t.Context(), "workspace-primary", []string{" user "})
		closeDB()
		if err == nil {
			t.Fatalf("projection failure %d was accepted", index)
		}
	}
	repository, closeDB := scriptedAuthStore(base, &authDBState{querySteps: []authMutationQueryStep{{columns: columns, rows: [][]driver.Value{{"user", "locked", "last", int64(2), true}}}}})
	facts, err := repository.ListUserProjectionSecurityFacts(t.Context(), "workspace-primary", []string{" user "})
	closeDB()
	if err != nil || len(facts) != 1 || facts[0].UserID != "user" || facts[0].ActiveSessions != 2 || !facts[0].MFAEnabled {
		t.Fatalf("facts=%#v err=%v", facts, err)
	}

	valid := identitymodel.IdentityMFAFactor{ID: "factor", UserID: "user", Type: "totp", Status: "active"}
	for name, factor := range map[string]identitymodel.IdentityMFAFactor{
		"id":     {UserID: valid.UserID, Type: valid.Type, Status: valid.Status},
		"user":   {ID: valid.ID, Type: valid.Type, Status: valid.Status},
		"type":   {ID: valid.ID, UserID: valid.UserID, Status: valid.Status},
		"status": {ID: valid.ID, UserID: valid.UserID, Type: valid.Type},
	} {
		if err := base.UpsertIdentityMFAFactor(t.Context(), "workspace-primary", factor); err == nil {
			t.Fatalf("MFA factor missing %s was accepted", name)
		}
	}
}

func authFailureBase(t *testing.T) AuthStore {
	t.Helper()
	store := openStoreForGeneratedListTest(t)
	t.Cleanup(func() { _ = store.Close() })
	identity, err := identitypersistence.NewSQLIdentityStore(t.Context(), store.DB(), store.PersistenceEngine())
	if err != nil {
		t.Fatal(err)
	}
	return NewAuthStore(identity)
}

func scriptedAuthStore(base AuthStore, state *authDBState) (AuthStore, func()) {
	db := sql.OpenDB(authConnector{state: state})
	base.db = db
	return base, func() { _ = db.Close() }
}

func authMutationRow(status, fingerprint string, expires time.Time, token int64) []driver.Value {
	return []driver.Value{"receipt", "workspace-primary", "reset", "user", "key", fingerprint, status, "{}", "worker", expires.Format(time.RFC3339Nano), token, "", "", "actor", "created", "updated"}
}

type authMutationQueryStep struct {
	columns []string
	rows    [][]driver.Value
	err     error
	nextErr error
}
type authExecStep struct {
	rows    int64
	err     error
	rowsErr error
}
type authDBState struct {
	querySteps []authMutationQueryStep
	execSteps  []authExecStep
	beginErr   error
	commitErr  error
}
type authConnector struct{ state *authDBState }

func (c authConnector) Connect(context.Context) (driver.Conn, error) {
	return &authConn{state: c.state}, nil
}
func (authConnector) Driver() driver.Driver { return authDriver{} }

type authDriver struct{}

func (authDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type authConn struct{ state *authDBState }

func (*authConn) Prepare(string) (driver.Stmt, error)                            { return nil, driver.ErrSkip }
func (*authConn) Close() error                                                   { return nil }
func (c *authConn) Begin() (driver.Tx, error)                                    { return c.begin() }
func (c *authConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.begin() }
func (c *authConn) begin() (driver.Tx, error) {
	if c.state.beginErr != nil {
		return nil, c.state.beginErr
	}
	return authTx{state: c.state}, nil
}
func (c *authConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if len(c.state.querySteps) == 0 {
		return &authRows{}, nil
	}
	step := c.state.querySteps[0]
	c.state.querySteps = c.state.querySteps[1:]
	if step.err != nil {
		return nil, step.err
	}
	return &authRows{columns: step.columns, rows: step.rows, nextErr: step.nextErr}, nil
}
func (c *authConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	if len(c.state.execSteps) == 0 {
		return authResult{rows: 1}, nil
	}
	step := c.state.execSteps[0]
	c.state.execSteps = c.state.execSteps[1:]
	return authResult{rows: step.rows, err: step.rowsErr}, step.err
}

type authTx struct{ state *authDBState }

func (t authTx) Commit() error { return t.state.commitErr }
func (authTx) Rollback() error { return nil }

type authResult struct {
	rows int64
	err  error
}

func (authResult) LastInsertId() (int64, error)   { return 0, nil }
func (r authResult) RowsAffected() (int64, error) { return r.rows, r.err }

type authRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
	nextErr error
}

func (r *authRows) Columns() []string { return r.columns }
func (*authRows) Close() error        { return nil }
func (r *authRows) Next(values []driver.Value) error {
	if r.index < len(r.rows) {
		copy(values, r.rows[r.index])
		r.index++
		return nil
	}
	if r.nextErr != nil {
		err := r.nextErr
		r.nextErr = nil
		return err
	}
	return io.EOF
}
