package identity

import (
	"database/sql"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

func (s *SQLIdentityStore) DB() *sql.DB { return s.db }

func (s *SQLIdentityStore) Driver() string { return s.driver }

func (s *SQLIdentityStore) MaxParameters() int { return s.engineProfile().MaxParameters() }

func (s *SQLIdentityStore) SQLRenderer() ormdialect.Renderer { return s.sqlRenderer() }

func (s *SQLIdentityStore) ApplyUpsert(insert *ormbuilder.InsertBuilder, conflictColumns []string, updateColumns ...string) *ormbuilder.InsertBuilder {
	return s.engineProfile().ApplyUpsert(insert, conflictColumns, updateColumns...)
}

func (s *SQLIdentityStore) Identifier(value string) string { return s.identifier(value) }

func (s *SQLIdentityStore) TableIdentifier(value string) string { return s.tableIdentifier(value) }

func (s *SQLIdentityStore) Placeholder(position int) string { return s.placeholder(position) }

func (s *SQLIdentityStore) IdentityColumns(columns ...string) string {
	return s.identityColumns(columns...)
}

func (s *SQLIdentityStore) Placeholders(count int) string { return s.placeholders(count) }

func NowString() string { return nowString() }

func ValueFromNull(value sql.NullString) string { return valueFromNull(value) }

func ScanAuthRefreshToken(scanner interface{ Scan(...any) error }) (identitymodel.AuthRefreshToken, error) {
	return scanAuthRefreshToken(scanner)
}
