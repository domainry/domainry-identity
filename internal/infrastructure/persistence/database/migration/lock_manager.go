package migration

import (
	"context"
	"database/sql"
	"time"

	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/driver"
	"github.com/domainry/domainry-identity/internal/platform/config"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type LockMetrics interface {
	ObserveMigrationLock(time.Duration, error)
}

type LockManager struct {
	database         *sql.DB
	engine           driver.Engine
	renderer         ormdialect.Renderer
	databaseSchema   string
	lockTimeout      time.Duration
	connectTimeout   time.Duration
	metrics          LockMetrics
	activeConnection *sql.Conn
}

func NewLockManager(database *sql.DB, engine driver.Engine, renderer ormdialect.Renderer, databaseSchema string, cfg config.Config, metrics LockMetrics) *LockManager {
	return &LockManager{database: database, engine: engine, renderer: renderer, databaseSchema: databaseSchema, lockTimeout: cfg.DatabaseLockTimeout, connectTimeout: cfg.DatabaseConnectTimeout, metrics: metrics}
}

func (manager *LockManager) Acquire(ctx context.Context, cfg config.Config) (func(), error) {
	started := time.Now()
	lock, err := manager.engine.AcquireMigrationLock(ctx, manager.database, manager.renderer, driver.MigrationLockOptions{
		DatabasePath: cfg.DBPath, DatabaseSchema: manager.databaseSchema, Owner: InstanceID(cfg),
		LockTimeout: manager.lockTimeout, ConnectTimeout: manager.connectTimeout,
	})
	if manager.metrics != nil {
		manager.metrics.ObserveMigrationLock(time.Since(started), err)
	}
	if err != nil {
		return nil, err
	}
	manager.activeConnection = lock.Connection
	return func() {
		manager.activeConnection = nil
		if lock.Release != nil {
			lock.Release()
		}
	}, nil
}

func (manager *LockManager) Connection() *sql.Conn {
	if manager == nil {
		return nil
	}
	return manager.activeConnection
}

func (manager *LockManager) Close() error {
	if manager == nil || manager.activeConnection == nil {
		return nil
	}
	err := manager.activeConnection.Close()
	manager.activeConnection = nil
	return err
}
