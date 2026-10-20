package module

import (
	"context"
	identitysdkadapter "github.com/domainry/domainry-identity/internal/adapter/identitysdk"
)

// BeginPrincipalResolutionScope reuses authoritative Identity reads only within
// one synchronous host evaluation. Always call end before external IO/execution.
func BeginPrincipalResolutionScope(ctx context.Context) (context.Context, func()) {
	return identitysdkadapter.BeginPrincipalResolutionScope(ctx)
}

func BeginPrincipalReadScope(ctx context.Context) (context.Context, func() error) {
	return identitysdkadapter.BeginPrincipalReadScope(ctx)
}
