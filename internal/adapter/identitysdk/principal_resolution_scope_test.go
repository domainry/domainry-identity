package identitysdkadapter

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
)

func TestPrincipalResolutionScopeReusesReadsWithoutSharingMutablePolicy(t *testing.T) {
	f := newPrincipalReadFixture(t)
	ctx, end := BeginPrincipalResolutionScope(f.ctx)
	defer end()
	request := identitysdk.PrincipalResolutionRequest{SubjectID: "subject", RoleKey: "reader"}
	for i := 0; i < 48; i++ {
		result, err := f.resolver.Resolve(ctx, request)
		if err != nil || result.Principal.Permissions[0] != "order.read" || result.AccessBundle.Subject.OrgID != "" {
			t.Fatalf("resolution %d: %+v %v", i, result, err)
		}
		result.Principal.Permissions[0] = "forged.permission"
		result.AccessBundle.Subject.OrgID = "forged-department"
	}
	if f.repo.users != 2 || f.repo.roles != 2 || f.repo.assignments != 2 {
		t.Fatalf("48 tools repeated owner IO: users=%d roles=%d assignments=%d", f.repo.users, f.repo.roles, f.repo.assignments)
	}
	if _, err := f.resolver.Resolve(ctx, identitysdk.PrincipalResolutionRequest{SubjectID: "subject", RoleKey: "writer"}); err != nil || f.repo.users != 4 {
		t.Fatalf("roles shared a cache entry: %v users=%d", err, f.repo.users)
	}
}

func TestPrincipalResolutionScopePreservesNumericPolicyValues(t *testing.T) {
	f := newPrincipalReadFixture(t)
	ctx, end := BeginPrincipalResolutionScope(f.ctx)
	defer end()
	request := identitysdk.PrincipalResolutionRequest{SubjectID: "subject", RoleKey: "reader"}
	result, err := f.resolver.Resolve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the exact cached wire contract. JSON's default float64 decoding
	// would silently round this policy value and change its meaning on a hit.
	result.AccessBundle.DataPolicies[0].Predicate = identitysdk.Predicate{Fact: "order_number", Operator: "eq", Value: json.Number("9007199254740993")}
	result.AccessBundle.DataPolicies[0].DataScopes = nil
	if err := result.AccessBundle.Validate(f.resolver.binding.clock.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := identityscope.ScopeFromContext(ctx)
	encodedRequest, _ := json.Marshal(request)
	memo := ctx.Value(principalResolutionScopeKey{}).(*principalResolutionScope)
	memo.values[principalResolutionKey{binding: f.resolver.binding, scope: scope, request: string(encodedRequest)}] = raw
	got, err := f.resolver.Resolve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if number, ok := got.AccessBundle.DataPolicies[0].Predicate.Value.(json.Number); !ok || string(number) != "9007199254740993" {
		t.Fatalf("cached policy number changed: %#v", got.AccessBundle.DataPolicies[0].Predicate.Value)
	}
}

func TestPrincipalResolutionScopeEndsBeforeRevokedToolExecution(t *testing.T) {
	f := newPrincipalReadFixture(t)
	ctx, end := BeginPrincipalResolutionScope(f.ctx)
	request := identitysdk.PrincipalResolutionRequest{SubjectID: "subject", RoleKey: "reader"}
	if _, err := f.resolver.Resolve(ctx, request); err != nil {
		t.Fatal(err)
	}
	end()
	if err := f.repo.RemoveIdentityUserRole(f.ctx, "workspace-primary", "subject", "reader-id"); err != nil {
		t.Fatal(err)
	}
	for _, check := range []context.Context{ctx, f.ctx} {
		if _, err := f.resolver.Resolve(check, request); err == nil {
			t.Fatal("ended catalog scope authorized a revoked role")
		}
	}
	fresh, closeFresh := BeginPrincipalResolutionScope(f.ctx)
	defer closeFresh()
	if _, err := f.resolver.Resolve(fresh, request); err == nil {
		t.Fatal("new model phase retained old role")
	}
}

func TestPrincipalResolutionScopeNeverHidesCancellationOrOwnerErrors(t *testing.T) {
	f := newPrincipalReadFixture(t)
	ctx, end := BeginPrincipalResolutionScope(f.ctx)
	defer end()
	request := identitysdk.PrincipalResolutionRequest{SubjectID: "subject", RoleKey: "reader"}
	if _, err := f.resolver.Resolve(ctx, request); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.resolver.Resolve(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached result ignored cancellation: %v", err)
	}
	other := f.resolver
	copyBinding := *f.resolver.binding
	other.binding = &copyBinding
	f.repo.fail, f.repo.users = "users", 1
	if _, err := other.Resolve(ctx, request); !errors.Is(err, f.repo.err) {
		t.Fatalf("cache crossed binding or swallowed owner error: %v", err)
	}
}

func TestPrincipalReadScopeRechecksCurrentOwnerBeforeRelease(t *testing.T) {
	for _, scenario := range []string{"unchanged", "revoked", "policy-changed", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPrincipalReadFixture(t)
			ctx, finish := BeginPrincipalReadScope(f.ctx)
			request := identitysdk.PrincipalResolutionRequest{SubjectID: "subject", RoleKey: "reader"}
			for i := 0; i < 48; i++ {
				if _, err := f.resolver.Resolve(ctx, request); err != nil {
					t.Fatal(err)
				}
			}
			if f.repo.users != 2 {
				t.Fatal("read snapshot was repeatedly rebuilt", f.repo.users)
			}
			switch scenario {
			case "revoked":
				if err := f.repo.RemoveIdentityUserRole(f.ctx, "workspace-primary", "subject", "reader-id"); err != nil {
					t.Fatal(err)
				}
			case "policy-changed":
				f.identity.ReplaceRoleDefinitions(nil)
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				// A fresh scope must fail even when its owner snapshot is empty.
				_, cancelFinish := BeginPrincipalReadScope(cancelled)
				if !errors.Is(cancelFinish(), context.Canceled) {
					t.Fatal("cancelled evaluation was released")
				}
			}
			err := finish()
			if scenario == "revoked" || scenario == "policy-changed" {
				if err == nil {
					t.Fatal("read released data after its authorization changed")
				}
			} else if err != nil || f.repo.users != 4 {
				t.Fatalf("finish did not freshly verify owner: reads=%d err=%v", f.repo.users, err)
			}
			before := f.repo.users
			_, _ = f.resolver.Resolve(ctx, request)
			if f.repo.users <= before {
				t.Fatal("finished read context retained cached authority")
			}
		})
	}
}
