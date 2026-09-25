package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	"github.com/domainry/domainry-identity/internal/infrastructure/persistence/database/transaction"
	"github.com/domainry/domainry-orm/query"
)

func (s *SQLIdentityStore) ApplyIdentityWorkflowWorkloadRelease(ctx context.Context, release identitymodel.IdentityWorkflowWorkloadRelease) ([]identitymodel.IdentityWorkflowWorkloadBinding, error) {
	workspaceID, err := identityWorkspaceID(release.WorkspaceID)
	if err != nil {
		return nil, err
	}
	var tx *sql.Tx
	if active := transaction.ExecutorFromContext(ctx); active != nil {
		return nil, fmt.Errorf("identity workflow workload release must own its atomic transaction")
	}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := nowString()
	nowMillis := timeMillis(now)
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(s.sqlRenderer(), "_identity_workflow_workload_bindings", workspaceID).
		Set("status", "inactive").Set("deactivated_at", nowMillis).Set("updated_at", nowMillis).
		Where(query.And(query.Equal("application_key", release.ApplicationKey), query.Equal("status", "active"))).Build()
	if err != nil {
		return nil, fmt.Errorf("build workflow workload deactivation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
		return nil, err
	}
	result := make([]identitymodel.IdentityWorkflowWorkloadBinding, 0, len(release.Bindings))
	for _, binding := range release.Bindings {
		actionsJSON, encodeErr := json.Marshal(binding.ActionKeys)
		if encodeErr != nil {
			return nil, encodeErr
		}
		insert := query.NewWorkspaceInsertBuilder(s.sqlRenderer(), "_identity_workflow_workload_bindings", workspaceID).
			Columns("id", "application_key", "subject_id", "workflow_key", "definition_version_id", "definition_version", "role_key", "action_keys_json", "release_id", "release_digest", "source_kind", "source_id", "status", "created_at", "updated_at", "deactivated_at").
			Values(identityID("workflow_workload", workspaceID, release.ApplicationKey, binding.WorkflowKey), release.ApplicationKey, binding.SubjectID, binding.WorkflowKey, binding.DefinitionVersionID, binding.DefinitionVersion, binding.RoleKey, string(actionsJSON), release.ReleaseID, release.ReleaseDigest, binding.SourceKind, binding.SourceID, "active", nowMillis, nowMillis, int64(0))
		s.ApplyUpsert(insert, []string{"workspace_id", "application_key", "workflow_key"}, "subject_id", "definition_version_id", "definition_version", "role_key", "action_keys_json", "release_id", "release_digest", "source_kind", "source_id", "status", "updated_at", "deactivated_at")
		statement, arguments, buildErr := insert.Build()
		if buildErr != nil {
			return nil, fmt.Errorf("build workflow workload binding upsert: %w", buildErr)
		}
		if _, err := tx.ExecContext(ctx, statement, arguments...); err != nil {
			return nil, err
		}
		binding.Status, binding.CreatedAt, binding.UpdatedAt, binding.DeactivatedAt = "active", now, now, ""
		result = append(result, binding)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLIdentityStore) GetIdentityWorkflowWorkloadBinding(ctx context.Context, workspaceID, applicationKey, workflowKey string) (identitymodel.IdentityWorkflowWorkloadBinding, bool, error) {
	workspaceID, err := identityWorkspaceID(workspaceID)
	if err != nil {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, err
	}
	statement, arguments, err := query.NewWorkspaceSelectBuilder(s.sqlRenderer(), "_identity_workflow_workload_bindings", workspaceID).
		Columns("subject_id", "workflow_key", "definition_version_id", "definition_version", "role_key", "action_keys_json", "release_id", "release_digest", "source_kind", "source_id", "status", "created_at", "updated_at", "deactivated_at").
		Where(query.And(query.Equal("application_key", applicationKey), query.Equal("workflow_key", workflowKey))).Limit(1).Build()
	if err != nil {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, err
	}
	var binding identitymodel.IdentityWorkflowWorkloadBinding
	var actionsJSON string
	var createdAt, updatedAt, deactivatedAt int64
	err = s.reader(ctx).QueryRowContext(ctx, statement, arguments...).Scan(&binding.SubjectID, &binding.WorkflowKey, &binding.DefinitionVersionID, &binding.DefinitionVersion, &binding.RoleKey, &actionsJSON, &binding.ReleaseID, &binding.ReleaseDigest, &binding.SourceKind, &binding.SourceID, &binding.Status, &createdAt, &updatedAt, &deactivatedAt)
	if err == sql.ErrNoRows {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, nil
	}
	if err != nil {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, err
	}
	if err := json.Unmarshal([]byte(actionsJSON), &binding.ActionKeys); err != nil {
		return identitymodel.IdentityWorkflowWorkloadBinding{}, false, err
	}
	binding.WorkspaceID, binding.ApplicationKey = workspaceID, applicationKey
	binding.CreatedAt, binding.UpdatedAt, binding.DeactivatedAt = timeString(createdAt), timeString(updatedAt), timeString(deactivatedAt)
	return binding, true, nil
}
