package schema

import (
	"context"
)

// EnsureMetadataSchema is retained as an assembly boundary. Metadata-owned
// Definitions and localization are installed by their source modules; Identity
// no longer owns a private metadata table.
func EnsureMetadataSchema(ctx context.Context, _ Store) error {
	return ctx.Err()
}
