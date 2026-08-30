package schema

import (
	"context"
	"fmt"
)

// EnsureEvidenceSchema owns Identity's immutable audit evidence.
func EnsureEvidenceSchema(ctx context.Context, s Store) error {
	return nil
}

// RemoveFrontendCapabilityRegistry retires the old deployment-evidence table.
// Identity administration visibility is derived from menus and effective
// permissions; it is not registered by a static frontend manifest.
func RemoveFrontendCapabilityRegistry(ctx context.Context, s Store) error {
	if _, err := s.SchemaDB().ExecContext(ctx, "DROP TABLE IF EXISTS "+s.TableIdentifier("frontend_capability_manifests")); err != nil {
		return fmt.Errorf("remove retired frontend capability registry: %w", err)
	}
	return nil
}
