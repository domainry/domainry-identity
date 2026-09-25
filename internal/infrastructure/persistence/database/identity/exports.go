package identity

import (
	"context"
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) DB() *sql.DB { return s.db }

func (s *SQLIdentityStore) MaxParameters() int { return s.engineProfile().MaxParameters() }

func (s *SQLIdentityStore) QueryIdentityContext(ctx context.Context, queryValue string, args ...any) (*sql.Rows, error) {
	return s.reader(ctx).QueryContext(ctx, queryValue, args...)
}

func (s *SQLIdentityStore) QueryIdentityRowContext(ctx context.Context, queryValue string, args ...any) *sql.Row {
	return s.reader(ctx).QueryRowContext(ctx, queryValue, args...)
}

func (s *SQLIdentityStore) SQLRenderer() ormdialect.Renderer { return s.sqlRenderer() }

func (s *SQLIdentityStore) ApplyUpsert(insert *query.InsertBuilder, conflictColumns []string, updateColumns ...string) *query.InsertBuilder {
	return s.engineProfile().ApplyUpsert(insert, conflictColumns, updateColumns...)
}

func NowString() string { return nowString() }

func TimeMillis(value any) int64 { return timeMillis(value) }

func TimeString(value int64) string { return timeString(value) }

func ValueFromNull(value sql.NullString) string { return valueFromNull(value) }

func ScanAuthRefreshToken(scanner interface{ Scan(...any) error }) (identitymodel.AuthRefreshToken, error) {
	return scanAuthRefreshToken(scanner)
}
