package migration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/domainry/domainry-identity/internal/platform/config"
)

func Identity(path string) (string, string) {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	parts := strings.SplitN(base, "_", 2)
	if len(parts) == 1 {
		return parts[0], parts[0]
	}
	return parts[0], parts[1]
}

func Kind(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "data_") || strings.HasPrefix(name, "metadata_") || strings.HasPrefix(name, "manifest_") {
		return "metadata_data"
	}
	return "schema"
}

func Operator(cfg config.Config) string {
	if value := strings.TrimSpace(cfg.MigrationOperator); value != "" {
		return value
	}
	return "runtime"
}

func InstanceID(cfg config.Config) string {
	if value := strings.TrimSpace(cfg.MigrationInstanceID); value != "" {
		return value
	}
	host, _ := os.Hostname()
	return strings.TrimSpace(host) + ":" + strconv.Itoa(os.Getpid())
}

func Checksum(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read migration checksum: %w", err)
	}
	return ChecksumBytes(raw), nil
}

func ChecksumBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func DurationMilliseconds(value time.Duration) string {
	return fmt.Sprintf("%dms", value.Milliseconds())
}

func SQLPaths(dir string, entries []os.DirEntry) []string {
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil
	}
	return paths
}

func Names(paths []string) []string {
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, filepath.Base(path))
	}
	sort.Strings(names)
	return names
}

func SplitSQLStatements(raw string) []string {
	sqlLines := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		sqlLines = append(sqlLines, line)
	}
	parts := strings.Split(strings.Join(sqlLines, "\n"), ";")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		if statement := strings.TrimSpace(part); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}
