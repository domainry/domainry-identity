package schema

import (
	"context"
	"fmt"
)

// EnsureMetadataSchema creates only the definition storage used by the
// Identity Admin metadata editor. Business-runtime, notification, scheduler,
// workflow and integration tables deliberately do not belong to this service.
func EnsureMetadataSchema(ctx context.Context, s Store) error {
	documentText := s.SchemaTypes().DocumentText
	// These baseline tables require engine-provided physical key/document types.
	// domainry-orm has no custom ColumnType for those exact definitions.
	if _, err := s.SchemaDB().ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.TableIdentifier("_identity_manifest_catalog")+" ("+
		s.Identifier("key")+" "+s.MetadataIDColumnType()+" PRIMARY KEY, "+
		s.Identifier("value")+" "+documentText+" NOT NULL, "+
		s.Identifier("updated_at")+" "+s.MetadataIDColumnType()+" NOT NULL)"); err != nil {
		return fmt.Errorf("create _identity_manifest_catalog: %w", err)
	}
	return nil
}
