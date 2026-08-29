package identity

import (
	"context"
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (s *SQLIdentityStore) DB() *sql.DB { return s.db }

func (s *SQLIdentityStore) MaxParameters() int { return s.engineProfile().MaxParameters() }

func (s *SQLIdentityStore) QueryIdentityContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.reader(ctx).QueryContext(ctx, query, args...)
}

func (s *SQLIdentityStore) QueryIdentityRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.reader(ctx).QueryRowContext(ctx, query, args...)
}

func (s *SQLIdentityStore) SQLRenderer() ormdialect.Renderer { return s.sqlRenderer() }

func (s *SQLIdentityStore) ApplyUpsert(insert *ormbuilder.InsertBuilder, conflictColumns []string, updateColumns ...string) *ormbuilder.InsertBuilder {
	return s.engineProfile().ApplyUpsert(insert, conflictColumns, updateColumns...)
}

func NowString() string { return nowString() }

func ValueFromNull(value sql.NullString) string { return valueFromNull(value) }

func ScanAuthRefreshToken(scanner interface{ Scan(...any) error }) (identitymodel.AuthRefreshToken, error) {
	return scanAuthRefreshToken(scanner)
}
