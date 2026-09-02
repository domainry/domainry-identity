package migration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-foundation/logging"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
	"go.uber.org/zap"
)

type backupDatabase interface {
	driver.SchemaDatabase
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type BackupMetrics interface {
	ObserveBackupSuccess(time.Time)
}

type BackupOptions struct {
	Database          backupDatabase
	Engine            driver.Engine
	Renderer          ormdialect.Renderer
	DatabaseSchema    string
	RelationPrefix    string
	SecretMaterialKey [32]byte
	Metrics           BackupMetrics
	Checksum          func(string) (string, error)
}

type BackupManager struct {
	database          backupDatabase
	engine            driver.Engine
	renderer          ormdialect.Renderer
	databaseSchema    string
	relationPrefix    string
	secretMaterialKey [32]byte
	metrics           BackupMetrics
	checksum          func(string) (string, error)
	ready             bool
	backupID          string
}

func NewBackupManager(options BackupOptions) *BackupManager {
	return &BackupManager{
		database: options.Database, engine: options.Engine, renderer: options.Renderer,
		databaseSchema: options.DatabaseSchema, relationPrefix: options.RelationPrefix,
		secretMaterialKey: options.SecretMaterialKey, metrics: options.Metrics, checksum: options.Checksum,
	}
}

func (manager *BackupManager) Ready() bool { return manager != nil && manager.ready }

func (manager *BackupManager) BackupID() string {
	if manager == nil {
		return ""
	}
	return manager.backupID
}

func (manager *BackupManager) Reset() {
	if manager != nil {
		manager.ready, manager.backupID = false, ""
	}
}

func (manager *BackupManager) EnsureForExistingData(ctx context.Context, cfg config.Config) error {
	if manager.ready {
		return nil
	}
	hasData, err := manager.HasExistingApplicationData(ctx)
	if err != nil {
		return fmt.Errorf("check existing data before migration backup: %w", err)
	}
	if !hasData {
		manager.ready = true
		manager.backupID = "bootstrap-empty"
		return nil
	}
	policy := manager.engine.MigrationBackupPolicy()
	if policy.LocalSnapshot {
		backupPath, err := manager.CreateSQLiteMigrationBackup(ctx, cfg)
		if err != nil {
			return err
		}
		manager.ready = true
		checksum, checksumErr := manager.backupChecksum(backupPath)
		if checksumErr != nil {
			return checksumErr
		}
		manager.backupID = policy.BackupIDPrefix + checksum[:16]
		logging.FromContext(ctx).Info(
			"database migration backup created",
			zap.String("backup_id", manager.backupID),
			zap.String("database_engine", policy.EvidenceEngine),
		)
		if manager.metrics != nil {
			manager.metrics.ObserveBackupSuccess(time.Now().UTC())
		}
		return nil
	}
	if strings.TrimSpace(policy.EvidenceEngine) == "" {
		return fmt.Errorf("database engine does not define a migration backup policy")
	}
	evidence, err := ValidateExternalBackupPolicy(policy, cfg.MigrationBackupEvidencePath)
	if err != nil {
		return err
	}
	if manager.metrics != nil {
		manager.metrics.ObserveBackupSuccess(evidence.VerifiedAt)
	}
	manager.backupID = evidence.BackupID
	manager.ready = true
	return nil
}

func (manager *BackupManager) backupChecksum(path string) (string, error) {
	if manager.checksum != nil {
		return manager.checksum(path)
	}
	return Checksum(path)
}

func ValidateExternalBackup(engineName, evidencePath string) (BackupEvidence, error) {
	policies := map[string]driver.MigrationBackupPolicy{
		"mysql":    {ExternalEvidence: true, EvidenceEngine: "mysql"},
		"postgres": {ExternalEvidence: true, EvidenceEngine: "postgres"},
	}
	policy, supported := policies[strings.TrimSpace(engineName)]
	if !supported {
		return BackupEvidence{}, fmt.Errorf("unsupported database driver %q", engineName)
	}
	return ValidateExternalBackupPolicy(policy, evidencePath)
}

func ValidateExternalBackupPolicy(policy driver.MigrationBackupPolicy, evidencePath string) (BackupEvidence, error) {
	engine := strings.TrimSpace(policy.EvidenceEngine)
	if !policy.ExternalEvidence || engine == "" {
		return BackupEvidence{}, fmt.Errorf("database engine %q does not support external backup evidence", engine)
	}
	if strings.TrimSpace(evidencePath) == "" {
		return BackupEvidence{}, fmt.Errorf("existing %s application data detected before pending migrations; MIGRATION_BACKUP_EVIDENCE_PATH with a verified backup_id is required", engine)
	}
	evidence, err := ReadBackupEvidence(evidencePath)
	if err != nil {
		return BackupEvidence{}, err
	}
	if evidence.Engine != engine {
		return BackupEvidence{}, fmt.Errorf("backup evidence engine %q does not match %q", evidence.Engine, engine)
	}
	return evidence, nil
}

func (manager *BackupManager) HasExistingApplicationData(ctx context.Context) (bool, error) {
	tables, err := manager.ApplicationTables(ctx)
	if err != nil {
		return false, err
	}
	for _, table := range tables {
		var count int
		statement, arguments, buildErr := query.NewSelectBuilder(manager.renderer, table).
			Projections(query.Project(query.CountAll())).Build()
		if buildErr != nil {
			return false, fmt.Errorf("build count %s: %w", table, buildErr)
		}
		if err := manager.database.QueryRowContext(ctx, statement, arguments...).Scan(&count); err != nil {
			return false, fmt.Errorf("count %s: %w", table, err)
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (manager *BackupManager) ApplicationTables(ctx context.Context) ([]string, error) {
	query := manager.engine.ApplicationTablesQuery(manager.renderer, manager.databaseSchema)
	if strings.TrimSpace(query.Statement) == "" {
		return nil, fmt.Errorf("unsupported database driver %q: application table introspection is unavailable", manager.engine.Name())
	}
	rows, err := manager.database.QueryContext(ctx, query.Statement, query.Arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		logicalName := name
		if manager.relationPrefix != "" {
			if !strings.HasPrefix(name, manager.relationPrefix) {
				continue
			}
			logicalName = strings.TrimPrefix(name, manager.relationPrefix)
		}
		if IsSystemTable(logicalName) {
			continue
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(tables)
	return tables, nil
}

func IsSystemTable(name string) bool {
	switch strings.TrimSpace(name) {
	case "", "_schema_migrations":
		return true
	default:
		return false
	}
}

func (manager *BackupManager) CreateSQLiteMigrationBackup(ctx context.Context, cfg config.Config) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	dbPath := strings.TrimSpace(cfg.DatabaseDSN)
	if dbPath == "" {
		dbPath = strings.TrimSpace(cfg.DBPath)
	}
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return "", fmt.Errorf("existing SQLite data detected but APP_DB_PATH is not a copyable file path; provide a file-backed database so Identity can create a verified encrypted backup")
	}
	if err := os.MkdirAll(cfg.MigrationBackupDir, 0o755); err != nil {
		return "", fmt.Errorf("create migration backup directory: %w", err)
	}
	backupPath := filepath.Join(cfg.MigrationBackupDir, filepath.Base(dbPath)+"."+time.Now().UTC().Format("20060102T150405Z")+".bak.enc")
	if _, err := os.Stat(backupPath); err == nil {
		return "", fmt.Errorf("sqlite migration backup already exists: %s", backupPath)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect sqlite migration backup: %w", err)
	}
	plainPath := backupPath + ".partial"
	if _, err := manager.database.ExecContext(ctx, "VACUUM INTO "+manager.renderer.Placeholder(1), plainPath); err != nil {
		_ = os.Remove(plainPath)
		return "", fmt.Errorf("create consistent sqlite migration backup: %w", err)
	}
	defer os.Remove(plainPath)
	if err := EncryptBackupFile(plainPath, backupPath, manager.secretMaterialKey[:]); err != nil {
		return "", fmt.Errorf("encrypt sqlite migration backup: %w", err)
	}
	return backupPath, nil
}
