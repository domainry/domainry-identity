package authoring

import (
	"context"
	"strings"
)

type trustedBuilderTaskIDKey struct{}

// WithTrustedBuilderTaskID records a Builder-Task-ID only after a trusted
// lifecycle boundary has verified it. Transport headers must not call this
// function directly.
func WithTrustedBuilderTaskID(ctx context.Context, builderTaskID string) context.Context {
	builderTaskID = strings.TrimSpace(builderTaskID)
	if ctx == nil || builderTaskID == "" {
		return ctx
	}
	return context.WithValue(ctx, trustedBuilderTaskIDKey{}, builderTaskID)
}

func TrustedBuilderTaskID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	builderTaskID, _ := ctx.Value(trustedBuilderTaskIDKey{}).(string)
	return strings.TrimSpace(builderTaskID)
}
