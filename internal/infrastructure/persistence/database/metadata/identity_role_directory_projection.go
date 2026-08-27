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
		update := "UPDATE " + r.store.TableIdentifier("identity_roles") + " SET " + r.store.Identifier("label") + " = " + r.store.Placeholder(1) + ", " + r.store.Identifier("status") + " = " + r.store.Placeholder(2) + ", " + r.store.Identifier("updated_at") + " = " + r.store.Placeholder(3) + " WHERE " + r.store.Identifier("workspace_id") + " = " + r.store.Placeholder(4) + " AND " + r.store.Identifier("role_key") + " = " + r.store.Placeholder(5)
		result, err := tx.ExecContext(ctx, update, label, string(identitymodel.IdentityStatusActive), now, workspaceID.String(), roleKey)
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
		columns := []string{"id", "workspace_id", "role_key", "label", "description", "status", "created_at", "updated_at"}
		values := []any{roleKey, workspaceID.String(), roleKey, label, "", string(identitymodel.IdentityStatusActive), now, now}
		query := "INSERT INTO " + r.store.TableIdentifier("identity_roles") + " (" + joinIdentifiers(r.store, columns...) + ") VALUES (" + joinPlaceholders(r.store, len(values)) + ")"
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return fmt.Errorf("insert role directory projection %s: %w", roleKey, err)
		}
		return nil
	case "archive", "delete":
		query := "UPDATE " + r.store.TableIdentifier("identity_roles") + " SET " + r.store.Identifier("status") + " = " + r.store.Placeholder(1) + ", " + r.store.Identifier("updated_at") + " = " + r.store.Placeholder(2) + " WHERE " + r.store.Identifier("workspace_id") + " = " + r.store.Placeholder(3) + " AND " + r.store.Identifier("role_key") + " = " + r.store.Placeholder(4)
		result, err := tx.ExecContext(ctx, query, string(identitymodel.IdentityStatusDisabled), now, workspaceID.String(), roleKey)
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
