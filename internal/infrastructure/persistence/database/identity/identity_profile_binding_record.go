package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	"github.com/domainry/domainry-orm/query"
)

// GetIdentityProfileBindingRecord reads only metadata-declared columns from a
// business object in the shared host database. The object and field names are
// trusted Identity metadata, never handler-provided database identifiers.
func (s *SQLIdentityStore) GetIdentityProfileBindingRecord(ctx context.Context, workspaceID string, object definitionmodel.ObjectSchema, profileID string) (map[string]any, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return nil, false, err
	}
	objectKey := strings.TrimSpace(object.Key)
	if objectKey == "" || strings.TrimSpace(profileID) == "" {
		return nil, false, fmt.Errorf("profile binding object and profile id are required")
	}
	columns := []string{"id", "workspace_id"}
	seen := map[string]struct{}{"id": {}, "workspace_id": {}}
	for _, field := range object.Fields {
		key := strings.TrimSpace(field.Key)
		if key == "" || strings.TrimSpace(field.DisabledAt) != "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		columns = append(columns, key)
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), objectKey, workspaceID).
		Columns(columns...).Where(query.Equal("id", strings.TrimSpace(profileID))).Limit(1).Build()
	if err != nil {
		return nil, false, fmt.Errorf("build profile binding record query: %w", err)
	}
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(destinations...); errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	record := make(map[string]any, len(columns))
	for index, column := range columns {
		if bytes, ok := values[index].([]byte); ok {
			record[column] = string(bytes)
		} else {
			record[column] = values[index]
		}
	}
	return record, true, nil
}
