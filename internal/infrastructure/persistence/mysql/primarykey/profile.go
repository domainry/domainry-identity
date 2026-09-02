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

func (Profile) EnsureCompositePrimaryKey(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, relationPrefix, table string, columns ...string) error {
	// MySQL key inspection and DROP/ADD PRIMARY KEY are server-catalog and
	// constraint-alter operations that domainry-orm does not expose.
	physicalTable := relationPrefix + table
	rows, err := database.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY' ORDER BY ORDINAL_POSITION", physicalTable)
	if err != nil {
		return fmt.Errorf("inspect MySQL primary key for %s: %w", table, err)
	}
	current := []string{}
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			_ = rows.Close()
			return err
		}
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
	alter := "ALTER TABLE " + renderer.Table(table)
	if len(current) > 0 {
		alter += " DROP PRIMARY KEY,"
	}
	alter += " ADD PRIMARY KEY (" + strings.Join(quoted, ", ") + ")"
	_, err = database.ExecContext(ctx, alter)
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
