package primarykey

import (
	"context"
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Profile struct{}

func NewProfile() Profile { return Profile{} }

func (Profile) EnsureCompositePrimaryKey(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, schema, relationPrefix, table string, columns ...string) error {
	if strings.TrimSpace(schema) == "" {
		schema = "public"
	}
	physicalTable := relationPrefix + table
	rows, err := database.QueryContext(ctx, "SELECT tc.constraint_name, kcu.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema AND tc.table_name = kcu.table_name WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = $1 AND tc.table_name = $2 ORDER BY kcu.ordinal_position", schema, physicalTable)
	if err != nil {
		return fmt.Errorf("inspect PostgreSQL primary key for %s: %w", table, err)
	}
	constraint, current := "", []string{}
	for rows.Next() {
		var name, column string
		if err := rows.Scan(&name, &column); err != nil {
			_ = rows.Close()
			return err
		}
		constraint = name
		current = append(current, column)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if columnsEqual(current, columns) {
		return nil
	}
	quoted := make([]string, len(columns))
	for index, column := range columns {
		quoted[index] = renderer.Identifier(column)
	}
	statement := "ALTER TABLE " + renderer.Table(table)
	if constraint != "" {
		statement += " DROP CONSTRAINT " + renderer.Identifier(constraint) + ","
	}
	statement += " ADD PRIMARY KEY (" + strings.Join(quoted, ", ") + ")"
	_, err = database.ExecContext(ctx, statement)
	return err
}

func columnsEqual(current, expected []string) bool {
	if len(current) != len(expected) {
		return false
	}
	for index := range current {
		if !strings.EqualFold(strings.TrimSpace(current[index]), strings.TrimSpace(expected[index])) {
			return false
		}
	}
	return true
}
