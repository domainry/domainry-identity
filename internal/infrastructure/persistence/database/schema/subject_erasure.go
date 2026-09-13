package schema

import (
	"context"
	"fmt"
	ormschema "github.com/domainry/domainry-orm/schema"
)

func ensureSubjectErasureSchema(ctx context.Context, s Store) error {
	statement, args, err := ormschema.NewTable(s.SchemaRenderer(), "_identity_subject_erasure_receipts").IfNotExists().Columns(
		ormschema.Column("id", ormschema.Varchar(64)).NotNull(),
		ormschema.Column("workspace_id", ormschema.Varchar(128)).NotNull(),
		ormschema.Column("request_id", ormschema.Varchar(128)).NotNull(),
		ormschema.Column("subject_id", ormschema.Varchar(128)).NotNull(),
		ormschema.Column("result_json", ormschema.Text()).NotNull(),
		ormschema.Column("created_at", ormschema.Varchar(64)).NotNull(),
	).PrimaryKey("id").Build()
	if err != nil {
		return fmt.Errorf("build Identity subject erasure receipts: %w", err)
	}
	if _, err = s.SchemaDB().ExecContext(ctx, statement, args...); err != nil {
		return err
	}
	return s.CreateIndexIfMissing(ctx, "_identity_subject_erasure_receipts", "uniq_identity_subject_erasure_request", true, "workspace_id", "request_id")
}
