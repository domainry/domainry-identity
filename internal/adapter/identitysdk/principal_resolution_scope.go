package identitysdkadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	identityscope "github.com/domainry/domainry-identity-sdk/application"
)

type principalResolutionScopeKey struct{}
type principalResolutionScope struct {
	mu     sync.Mutex
	closed bool
	values map[principalResolutionKey][]byte
}
type principalResolutionKey struct {
	binding *sdkBinding
	scope   identitysdk.ApplicationScope
	request string
}

// BeginPrincipalResolutionScope bounds reuse to one host-controlled catalog
// evaluation. It is not a session/TTL cache. Hosts must end it before model IO
// or executing a business operation, where current owner state is resolved again.
func BeginPrincipalResolutionScope(ctx context.Context) (context.Context, func()) {
	scope := &principalResolutionScope{values: make(map[principalResolutionKey][]byte)}
	return context.WithValue(ctx, principalResolutionScopeKey{}, scope), func() {
		scope.mu.Lock()
		defer scope.mu.Unlock()
		scope.closed = true
		scope.values = nil
	}
}

// BeginPrincipalReadScope allows one read-only authorization evaluation to use
// a coherent owner snapshot. Before any data can leave that evaluation, finish
// closes the memo and freshly resolves every reused principal/revision. A role
// or policy change during the read therefore rejects the complete evaluation.
// Never span a model request, a business write or a public request boundary.
func BeginPrincipalReadScope(ctx context.Context) (context.Context, func() error) {
	ctx, end := BeginPrincipalResolutionScope(ctx)
	memo := ctx.Value(principalResolutionScopeKey{}).(*principalResolutionScope)
	return ctx, func() error {
		memo.mu.Lock()
		if memo.closed {
			memo.mu.Unlock()
			return nil
		}
		values := memo.values
		memo.closed, memo.values = true, nil
		memo.mu.Unlock()
		defer end()
		for key, saved := range values {
			var request identitysdk.PrincipalResolutionRequest
			var previous identitysdk.PrincipalResolution
			if err := json.Unmarshal([]byte(key.request), &request); err != nil {
				return err
			}
			if err := json.Unmarshal(saved, &previous); err != nil {
				return err
			}
			fresh, err := (sdkPrincipalResolver{binding: key.binding}).resolve(identityscope.WithScope(ctx, key.scope), request)
			if err != nil {
				return err
			}
			if fresh.AccessBundle.AuthorizationRevision != previous.AccessBundle.AuthorizationRevision {
				return &identitysdk.Error{StatusCode: http.StatusUnauthorized, Code: "identity.authorization_revision_stale"}
			}
		}
		return ctx.Err()
	}
}

func (adapter sdkPrincipalResolver) Resolve(ctx context.Context, request identitysdk.PrincipalResolutionRequest) (identitysdk.PrincipalResolution, error) {
	if err := ctx.Err(); err != nil {
		return identitysdk.PrincipalResolution{}, err
	}
	memo, _ := ctx.Value(principalResolutionScopeKey{}).(*principalResolutionScope)
	application, scoped := identityscope.ScopeFromContext(ctx)
	if memo == nil || !scoped {
		return adapter.resolve(ctx, request)
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return identitysdk.PrincipalResolution{}, err
	}
	key := principalResolutionKey{binding: adapter.binding, scope: application, request: string(raw)}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return identitysdk.PrincipalResolution{}, err
	}
	if memo.closed {
		return adapter.resolve(ctx, request)
	}
	if saved, found := memo.values[key]; found {
		var result identitysdk.PrincipalResolution
		decoder := json.NewDecoder(bytes.NewReader(saved))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return result, err
		}
		if err := result.AccessBundle.Validate(adapter.binding.clock.Now().UTC()); err == nil {
			return result, nil
		}
		delete(memo.values, key)
	}
	result, err := adapter.resolve(ctx, request)
	if err != nil {
		return result, err
	}
	// Store bytes, never caller-owned slices, predicates or policy maps.
	if len(memo.values) < 128 {
		saved, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return identitysdk.PrincipalResolution{}, marshalErr
		}
		memo.values[key] = saved
	}
	return result, nil
}
