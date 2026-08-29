package primarykey

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type columnDefinition struct {
	position     int
	name         string
	typeName     string
	notNull      bool
	defaultValue sql.NullString
	primaryOrder int
}

type Profile struct{}

func NewProfile() Profile { return Profile{} }

func (Profile) EnsureCompositePrimaryKey(ctx context.Context, database driver.SchemaDatabase, renderer ormdialect.Renderer, _, relationPrefix, table string, columns ...string) error {
	physicalTable := relationPrefix + table
	rows, err := database.QueryContext(ctx, "PRAGMA table_info("+renderer.Identifier(physicalTable)+")")
	if err != nil {
		return fmt.Errorf("inspect SQLite primary key for %s: %w", table, err)
	}
	definitions := []columnDefinition{}
	for rows.Next() {
		var column columnDefinition
		var notNull int
		if err := rows.Scan(&column.position, &column.name, &column.typeName, &notNull, &column.defaultValue, &column.primaryOrder); err != nil {
			_ = rows.Close()
			return err
		}
		column.notNull = notNull != 0
		definitions = append(definitions, column)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	current := primaryKeyColumns(definitions)
	if equalPrimaryKey(current, columns) {
		return nil
	}
	if len(definitions) == 0 {
		return fmt.Errorf("SQLite table %s is unavailable", table)
	}
	temporary := table + "__composite_pk"
	columnSQL := make([]string, 0, len(definitions)+1)
	columnNames := make([]string, 0, len(definitions))
	for _, column := range definitions {
		definition := renderer.Identifier(column.name)
		if strings.TrimSpace(column.typeName) != "" {
			definition += " " + column.typeName
		}
		if column.notNull {
			definition += " NOT NULL"
		}
		if column.defaultValue.Valid {
			definition += " DEFAULT " + column.defaultValue.String
		}
		columnSQL = append(columnSQL, definition)
		columnNames = append(columnNames, renderer.Identifier(column.name))
	}
	primary := make([]string, len(columns))
	for index, column := range columns {
		primary[index] = renderer.Identifier(column)
	}
	columnSQL = append(columnSQL, "PRIMARY KEY ("+strings.Join(primary, ", ")+")")
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+renderer.Table(temporary)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "CREATE TABLE "+renderer.Table(temporary)+" ("+strings.Join(columnSQL, ", ")+")"); err != nil {
		return fmt.Errorf("create SQLite primary-key migration table %s: %w", table, err)
	}
	joined := strings.Join(columnNames, ", ")
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+renderer.Table(temporary)+" ("+joined+") SELECT "+joined+" FROM "+renderer.Table(table)); err != nil {
		return fmt.Errorf("copy SQLite primary-key migration table %s: %w", table, err)
	}
	if _, err := tx.ExecContext(ctx, "DROP TABLE "+renderer.Table(table)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "ALTER TABLE "+renderer.Table(temporary)+" RENAME TO "+renderer.Identifier(physicalTable)); err != nil {
		return err
	}
	return tx.Commit()
}

func primaryKeyColumns(columns []columnDefinition) []string {
	key := make([]columnDefinition, 0)
	for _, column := range columns {
		if column.primaryOrder > 0 {
			key = append(key, column)
		}
	}
	sort.Slice(key, func(left, right int) bool { return key[left].primaryOrder < key[right].primaryOrder })
	result := make([]string, len(key))
	for index, column := range key {
		result[index] = column.name
	}
	return result
}

func equalPrimaryKey(current, expected []string) bool {
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
