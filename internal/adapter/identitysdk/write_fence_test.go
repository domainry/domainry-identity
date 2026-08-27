package identitysdkadapter

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type mutationFenceStub struct {
	frozen bool
	err    error
}

func (stub mutationFenceStub) IdentityWritesFrozen(context.Context, string) (bool, error) {
	return stub.frozen, stub.err
}

type loginTransactionStub struct {
	workspaceID string
	found       bool
	err         error
}

func (stub loginTransactionStub) FederatedLoginWorkspace(context.Context, string, string, time.Time) (string, bool, error) {
	return stub.workspaceID, stub.found, stub.err
}

type fixedSDKClock struct{ now time.Time }

func (clock fixedSDKClock) Now() time.Time { return clock.now }

func TestSDKMutationFenceFailsClosedForFrozenAndUnavailableWorkspaces(t *testing.T) {
	for name, fixture := range map[string]struct {
		fence  mutationFenceStub
		code   string
		status int
	}{
		"frozen":      {fence: mutationFenceStub{frozen: true}, code: "identity.workspace_writes_frozen", status: http.StatusLocked},
		"unavailable": {fence: mutationFenceStub{err: errors.New("database unavailable")}, code: "identity.write_fence_unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			binding := &sdkBinding{mutationFence: fixture.fence}
			err := binding.requireMutableWorkspace(t.Context(), "workspace-a")
			var sdkError *identitysdk.Error
			if !errors.As(err, &sdkError) || sdkError.Code != fixture.code || sdkError.StatusCode != fixture.status {
				t.Fatalf("error=%#v", err)
			}
		})
	}
}

func TestFederatedLoginFenceResolvesOnlyTheOpaqueStatesWorkspace(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	binding := &sdkBinding{
		clock:             fixedSDKClock{now: now},
		loginTransactions: loginTransactionStub{workspaceID: "workspace-b", found: true},
	}
	workspaceID, err := binding.federatedLoginWorkspace(t.Context(), "oidc", "opaque-state")
	if err != nil || workspaceID != "workspace-b" {
		t.Fatalf("workspace=%q err=%v", workspaceID, err)
	}
	binding.loginTransactions = loginTransactionStub{}
	if _, err := binding.federatedLoginWorkspace(t.Context(), "oidc", "unknown"); err == nil {
		t.Fatal("unknown federated-login state was accepted")
	}
}
