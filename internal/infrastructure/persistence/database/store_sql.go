package database

import (
	"context"
	"fmt"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/base"
	ormbuilder "github.com/domainry/domainry-orm/builder"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

// BuilderRenderer exposes only the structured SQL rendering contract to
// repository adapters that deliberately hide the concrete database owner.
func (s *IdentityStore) BuilderRenderer() ormdialect.Renderer {
	return s.sqlBase().SQLRenderer
}

func (s *IdentityStore) sqlBase() *base.SQLDatabase {
	if s.SQLDatabase == nil {
		s.SQLDatabase = base.NewSQLDatabase(s.db, s.engine, s.databaseSchema, s.relationPrefix)
	}
	return s.SQLDatabase
}

func (s *IdentityStore) EnsureCompositePrimaryKey(ctx context.Context, table string, columns ...string) error {
	base := s.sqlBase()
	return base.Engine.EnsureCompositePrimaryKey(ctx, s.schemaDatabase(), base.SQLRenderer, base.DatabaseSchema, base.RelationPrefix, table, columns...)
}

func (s *IdentityStore) insertSystemRowContext(ctx context.Context, table string, columns []string, values []any) error {
	query, args, err := ormbuilder.NewInsertBuilder(s.sqlBase().SQLRenderer, table).Columns(columns...).Values(values...).Build()
	if err != nil {
		return fmt.Errorf("build insert %s: %w", table, err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("insert %s: %w", table, err)
	}
	return nil
}

func (s *IdentityStore) updateSystemRowContext(ctx context.Context, table, id string, columns []string, values []any) error {
	builder := ormbuilder.NewUpdateBuilder(s.sqlBase().SQLRenderer, table)
	for index, column := range columns {
		builder.Set(column, values[index])
	}
	query, args, err := builder.Where(ormbuilder.Equal("id", id)).Build()
	if err != nil {
		return fmt.Errorf("build update %s: %w", table, err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("update %s: %w", table, err)
	}
	return nil
}

func quotedColumns(s *IdentityStore, columns []string) []string {
	quoted := make([]string, 0, len(columns))
	for _, column := range columns {
		quoted = append(quoted, s.identifier(column))
	}
	return quoted
}

func placeholders(s *IdentityStore, count int) []string {
	values := make([]string, 0, count)
	for idx := 0; idx < count; idx++ {
		values = append(values, s.placeholder(idx+1))
	}
	return values
}

func (s *IdentityStore) identifier(value string) string {
	return s.sqlBase().SQLRenderer.Identifier(value)
}

func (s *IdentityStore) tableIdentifier(value string) string {
	return s.sqlBase().SQLRenderer.Table(value)
}

// Identifier exposes the database-specific quoting policy to domain-owned
// repository adapters without exposing Store internals.
func (s *IdentityStore) Identifier(value string) string {
	return s.identifier(value)
}

// TableIdentifier schema-qualifies PostgreSQL relations while leaving column,
// constraint, and index identifiers unqualified.
func (s *IdentityStore) TableIdentifier(value string) string {
	return s.tableIdentifier(value)
}

func (s *IdentityStore) placeholder(position int) string {
	return s.sqlBase().SQLRenderer.Placeholder(position)
}

// Placeholder exposes the database-specific placeholder syntax to
// domain-owned repository adapters.
func (s *IdentityStore) Placeholder(position int) string {
	return s.placeholder(position)
}
