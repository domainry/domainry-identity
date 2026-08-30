package migration

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
)

type CommandSpec struct {
	Executable  string            `json:"executable"`
	Arguments   []string          `json:"arguments"`
	Environment map[string]string `json:"-"`
	StdinPath   string            `json:"stdin_path,omitempty"`
}

type externalCommandProfile interface {
	Backup(string, string) (CommandSpec, error)
	Restore(string, string) (CommandSpec, error)
}

type postgresCommandProfile struct{}

func (postgresCommandProfile) Backup(dsn, target string) (CommandSpec, error) {
	return CommandSpec{Executable: "pg_dump", Arguments: []string{"--format=custom", "--no-owner", "--file", target, dsn}}, nil
}
func (postgresCommandProfile) Restore(dsn, source string) (CommandSpec, error) {
	return CommandSpec{Executable: "pg_restore", Arguments: []string{"--clean", "--if-exists", "--no-owner", "--dbname", dsn, source}}, nil
}

type mysqlCommandProfile struct{}

func (mysqlCommandProfile) Backup(dsn, target string) (CommandSpec, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return CommandSpec{}, fmt.Errorf("parse mysql DSN: %w", err)
	}
	args := append(mysqlConnectionArguments(cfg), "--single-transaction", "--routines", "--events", "--result-file="+target, cfg.DBName)
	return CommandSpec{Executable: "mysqldump", Arguments: args, Environment: map[string]string{"MYSQL_PWD": cfg.Passwd}}, nil
}
func (mysqlCommandProfile) Restore(dsn, source string) (CommandSpec, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return CommandSpec{}, fmt.Errorf("parse mysql DSN: %w", err)
	}
	args := append(mysqlConnectionArguments(cfg), cfg.DBName)
	return CommandSpec{Executable: "mysql", Arguments: args, Environment: map[string]string{"MYSQL_PWD": cfg.Passwd}, StdinPath: source}, nil
}

var externalCommandProfiles = map[string]externalCommandProfile{
	"postgres": postgresCommandProfile{}, "postgresql": postgresCommandProfile{}, "pgx": postgresCommandProfile{},
	"mysql": mysqlCommandProfile{},
}

func externalCommands(engine string) (externalCommandProfile, error) {
	profile := externalCommandProfiles[strings.ToLower(strings.TrimSpace(engine))]
	if profile == nil {
		return nil, fmt.Errorf("external database command profile is unavailable for %q", engine)
	}
	return profile, nil
}

func DatabaseBackupCommand(engine, dsn, target string) (CommandSpec, error) {
	profile, err := externalCommands(engine)
	if err != nil {
		return CommandSpec{}, err
	}
	return profile.Backup(dsn, target)
}

func DatabaseRestoreCommand(engine, dsn, source string) (CommandSpec, error) {
	profile, err := externalCommands(engine)
	if err != nil {
		return CommandSpec{}, err
	}
	return profile.Restore(dsn, source)
}

func mysqlConnectionArguments(cfg *mysqldriver.Config) []string {
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		host = cfg.Addr
	}
	args := []string{"--host", host, "--user", cfg.User}
	if port != "" {
		if _, err := strconv.Atoi(port); err == nil {
			args = append(args, "--port", port)
		}
	}
	if cfg.TLSConfig != "" {
		args = append(args, "--ssl-mode=VERIFY_IDENTITY")
	}
	return args
}
