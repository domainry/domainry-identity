package metadata

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

// applyIdentityRoleDirectoryMutation keeps the operational role directory and
// the published RoleSchema head in the same database transaction. The
// directory carries identity and assignment facts only; authorization policy
// remains exclusively owned by the published RoleSchema.
func (r MetadataStore) applyIdentityRoleDirectoryMutation(ctx context.Context, tx *sql.Tx, publication *changeplanmodel.BusinessChangePlanPublication, mutation metadatamodel.MetadataDefinitionMutation, definition metadatamodel.MetadataDefinition) error {
	if strings.TrimSpace(mutation.ResourceType) != "role" || mutation.Operation == "noop" {
		return nil
	}
	if publication == nil {
		return fmt.Errorf("role metadata mutation requires a system draft publication")
	}
	workspaceID, err := identitymodel.NewWorkspaceID(publication.WorkspaceID)
	if err != nil {
		return err
	}
	roleKey := strings.TrimSpace(mutation.ResourceKey)
	if roleKey == "" {
		return fmt.Errorf("role directory projection key is required")
	}
	now := definition.UpdatedAt
	if now == "" {
		now = definition.DisabledAt
	}

	switch mutation.Operation {
	case "create", "update":
		var role identitymodel.RoleSchema
		if err := json.Unmarshal(definition.Payload, &role); err != nil {
			return fmt.Errorf("decode role directory projection %s: %w", roleKey, err)
		}
		if strings.TrimSpace(role.Key) != roleKey {
			return fmt.Errorf("role directory projection identity mismatch: %s", roleKey)
		}
		label := strings.TrimSpace(role.Name)
		if label == "" {
			label = roleKey
		}
		statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(r.store.SQLRenderer, "identity_roles", workspaceID.String()).
			Set("label", label).Set("status", string(identitymodel.IdentityStatusActive)).Set("updated_at", now).
			Where(ormbuilder.Equal("role_key", roleKey)).Build()
		if err != nil {
			return fmt.Errorf("build role directory projection %s update: %w", roleKey, err)
		}
		result, err := tx.ExecContext(ctx, statement, arguments...)
		if err != nil {
			return fmt.Errorf("update role directory projection %s: %w", roleKey, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read updated role directory projection %s rows: %w", roleKey, err)
		}
		if affected == 1 {
			return nil
		}
		if affected != 0 {
			return fmt.Errorf("role directory projection %s is not unique", roleKey)
		}
		statement, arguments, err = ormbuilder.NewWorkspaceInsertBuilder(r.store.SQLRenderer, "identity_roles", workspaceID.String()).
			Columns("id", "role_key", "label", "description", "status", "created_at", "updated_at").
			Values(roleKey, roleKey, label, "", string(identitymodel.IdentityStatusActive), now, now).Build()
		if err != nil {
			return fmt.Errorf("build role directory projection %s insert: %w", roleKey, err)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return fmt.Errorf("insert role directory projection %s: %w", roleKey, err)
		}
		return nil
	case "archive", "delete":
		statement, arguments, err := ormbuilder.NewWorkspaceUpdateBuilder(r.store.SQLRenderer, "identity_roles", workspaceID.String()).
			Set("status", string(identitymodel.IdentityStatusDisabled)).Set("updated_at", now).Where(ormbuilder.Equal("role_key", roleKey)).Build()
		if err != nil {
			return fmt.Errorf("build role directory projection %s disable: %w", roleKey, err)
		}
		result, err := tx.ExecContext(ctx, statement, arguments...)
		if err != nil {
			return fmt.Errorf("disable role directory projection %s: %w", roleKey, err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read disabled role directory projection %s rows: %w", roleKey, err)
		}
		if affected != 1 {
			return fmt.Errorf("role directory projection %s not found", roleKey)
		}
		return nil
	default:
		return nil
	}
}
