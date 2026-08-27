package database

import (
	"context"
	"fmt"
	"strings"
)

func (s *IdentityStore) insertSystemRowContext(ctx context.Context, table string, columns []string, values []any) error {
	query := "INSERT INTO " + s.tableIdentifier(table) + " (" + strings.Join(quotedColumns(s, columns), ", ") + ") VALUES (" + strings.Join(placeholders(s, len(columns)), ", ") + ")"
	if _, err := s.db.ExecContext(ctx, query, values...); err != nil {
		return fmt.Errorf("insert %s: %w", table, err)
	}
	return nil
}

func (s *IdentityStore) updateSystemRowContext(ctx context.Context, table, id string, columns []string, values []any) error {
	assignments := make([]string, 0, len(columns))
	for index, column := range columns {
		assignments = append(assignments, s.identifier(column)+" = "+s.placeholder(index+1))
	}
	values = append(values, id)
	query := "UPDATE " + s.tableIdentifier(table) + " SET " + strings.Join(assignments, ", ") + " WHERE " + s.identifier("id") + " = " + s.placeholder(len(values))
	if _, err := s.db.ExecContext(ctx, query, values...); err != nil {
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
	return s.dialect.Identifier(value)
}

func (s *IdentityStore) tableIdentifier(value string) string {
	if s.dialect.Name() == "postgres" && strings.TrimSpace(s.databaseSchema) != "" {
		return s.dialect.Identifier(s.databaseSchema) + "." + s.dialect.Identifier(value)
	}
	return s.dialect.Identifier(value)
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
	return s.dialect.Placeholder(position)
}

// Placeholder exposes the database-specific placeholder syntax to
// domain-owned repository adapters.
func (s *IdentityStore) Placeholder(position int) string {
	return s.placeholder(position)
}
