package connection

import (
	"fmt"
	"strings"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/mysql"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/postgres"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/sqlite"
)

var engineRegistry = map[string]func() driver.Engine{
	"":           func() driver.Engine { return sqlite.NewEngine() },
	"sqlite":     func() driver.Engine { return sqlite.NewEngine() },
	"sqlite3":    func() driver.Engine { return sqlite.NewEngine() },
	"mysql":      func() driver.Engine { return mysql.NewEngine() },
	"postgres":   func() driver.Engine { return postgres.NewEngine() },
	"postgresql": func() driver.Engine { return postgres.NewEngine() },
	"pgx":        func() driver.Engine { return postgres.NewEngine() },
}

// EngineFor constructs the complete database engine selected by configuration.
func EngineFor(driverName string) (driver.Engine, error) {
	factory, found := engineRegistry[strings.ToLower(strings.TrimSpace(driverName))]
	if !found {
		return nil, fmt.Errorf("unsupported database driver %q", driverName)
	}
	return factory(), nil
}
