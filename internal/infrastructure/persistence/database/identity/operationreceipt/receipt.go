package operationreceipt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

const Table = "_operations"

type Queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type Receipt struct {
	ID                 string
	ResourceID         string
	RequestFingerprint string
	RequestedBy        string
	Reference          string
	ResultJSON         json.RawMessage
	CreatedAt          string
	Status             string
}

type Succeeded struct {
	ID                 string
	WorkspaceID        string
	Owner              string
	Kind               string
	ActionKey          string
	ResourceType       string
	ResourceID         string
	IdempotencyKey     string
	RequestFingerprint string
	RequestedBy        string
	Reason             string
	Reference          string
	ResultJSON         json.RawMessage
	MetadataJSON       json.RawMessage
	RelatedIDsJSON     json.RawMessage
	EvidenceJSON       json.RawMessage
	Correlation        string
	CompletedAt        string
}

func Load(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, idempotencyKey string) (Receipt, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(renderer, Table, strings.TrimSpace(workspaceID)).
		Columns("id", "resource_id", "request_fingerprint", "requested_by", "result_json", "created_at", "status").
		Where(query.And(
			query.Equal("system_purpose", ""),
			query.Equal("owner", strings.TrimSpace(owner)),
			query.Equal("kind", strings.TrimSpace(kind)),
			query.Equal("idempotency_key", strings.TrimSpace(idempotencyKey)),
		)).Build()
	if err != nil {
		return Receipt{}, false, err
	}
	return scanReceipt(queryer.QueryRowContext(ctx, statement, arguments...), false)
}

func LoadReferenced(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, idempotencyKey string) (Receipt, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(renderer, Table, strings.TrimSpace(workspaceID)).
		Columns("id", "resource_id", "request_fingerprint", "requested_by", "reference", "result_json", "created_at", "status").
		Where(query.And(
			query.Equal("system_purpose", ""),
			query.Equal("owner", strings.TrimSpace(owner)),
			query.Equal("kind", strings.TrimSpace(kind)),
			query.Equal("idempotency_key", strings.TrimSpace(idempotencyKey)),
		)).Build()
	if err != nil {
		return Receipt{}, false, err
	}
	return scanReceipt(queryer.QueryRowContext(ctx, statement, arguments...), true)
}

func LoadByID(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, id string) (Receipt, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(renderer, Table, strings.TrimSpace(workspaceID)).
		Columns("id", "resource_id", "request_fingerprint", "requested_by", "reference", "result_json", "created_at", "status").
		Where(query.And(
			query.Equal("system_purpose", ""),
			query.Equal("owner", strings.TrimSpace(owner)),
			query.Equal("kind", strings.TrimSpace(kind)),
			query.Equal("id", strings.TrimSpace(id)),
		)).Limit(1).Build()
	if err != nil {
		return Receipt{}, false, err
	}
	return scanReceipt(queryer.QueryRowContext(ctx, statement, arguments...), true)
}

func UpdateSucceededResult(ctx context.Context, execer Execer, renderer ormdialect.Renderer, workspaceID, owner, kind, id string, previous, next json.RawMessage, updatedAt string) (bool, error) {
	if !json.Valid(previous) || !json.Valid(next) || strings.TrimSpace(updatedAt) == "" {
		return false, fmt.Errorf("identity shared operation result update is invalid")
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(renderer, Table, strings.TrimSpace(workspaceID)).
		Set("result_json", string(next)).Set("updated_at", strings.TrimSpace(updatedAt)).
		Where(query.And(
			query.Equal("system_purpose", ""),
			query.Equal("owner", strings.TrimSpace(owner)),
			query.Equal("kind", strings.TrimSpace(kind)),
			query.Equal("id", strings.TrimSpace(id)),
			query.Equal("status", "succeeded"),
			query.Equal("result_json", string(previous)),
		)).Build()
	if err != nil {
		return false, err
	}
	result, err := execer.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func scanReceipt(row *sql.Row, withReference bool) (Receipt, bool, error) {
	var receipt Receipt
	var raw string
	var err error
	if withReference {
		err = row.Scan(&receipt.ID, &receipt.ResourceID, &receipt.RequestFingerprint, &receipt.RequestedBy, &receipt.Reference, &raw, &receipt.CreatedAt, &receipt.Status)
	} else {
		err = row.Scan(&receipt.ID, &receipt.ResourceID, &receipt.RequestFingerprint, &receipt.RequestedBy, &raw, &receipt.CreatedAt, &receipt.Status)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	receipt.ResultJSON = json.RawMessage(raw)
	if receipt.Status != "succeeded" || !json.Valid(receipt.ResultJSON) {
		return Receipt{}, false, fmt.Errorf("identity shared operation receipt invalid")
	}
	return receipt, true, nil
}

func InsertSucceeded(ctx context.Context, execer Execer, renderer ormdialect.Renderer, receipt Succeeded) error {
	for _, value := range []string{receipt.ID, receipt.WorkspaceID, receipt.Owner, receipt.Kind, receipt.ActionKey, receipt.ResourceType, receipt.IdempotencyKey, receipt.RequestFingerprint, receipt.RequestedBy, receipt.Reason, receipt.CompletedAt} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("identity shared operation receipt fields are required")
		}
	}
	if !json.Valid(receipt.ResultJSON) {
		return fmt.Errorf("identity shared operation result is invalid")
	}
	if len(receipt.MetadataJSON) == 0 {
		receipt.MetadataJSON = json.RawMessage(`{}`)
	}
	if len(receipt.RelatedIDsJSON) == 0 {
		receipt.RelatedIDsJSON = json.RawMessage(`[]`)
	}
	if len(receipt.EvidenceJSON) == 0 {
		receipt.EvidenceJSON = json.RawMessage(`[]`)
	}
	if !json.Valid(receipt.MetadataJSON) || !json.Valid(receipt.RelatedIDsJSON) || !json.Valid(receipt.EvidenceJSON) {
		return fmt.Errorf("identity shared operation metadata is invalid")
	}
	statement, arguments, err := query.NewWorkspaceInsertBuilder(renderer, Table, strings.TrimSpace(receipt.WorkspaceID)).
		Columns(
			"id", "system_purpose", "owner", "kind", "action_key", "parent_id", "resource_type", "resource_id",
			"idempotency_key", "request_fingerprint", "requested_by", "reason", "reference", "status", "status_url",
			"result_json", "metadata_json", "error_code", "failure_class", "next_action", "related_ids_json", "correlation",
			"evidence_json", "lease_owner", "lease_expires_at", "fencing_token", "expires_at", "created_at", "started_at",
			"finished_at", "updated_at",
		).
		Values(
			receipt.ID, "", receipt.Owner, receipt.Kind, receipt.ActionKey, "", receipt.ResourceType, receipt.ResourceID,
			receipt.IdempotencyKey, receipt.RequestFingerprint, receipt.RequestedBy, receipt.Reason, receipt.Reference, "succeeded", "",
			string(receipt.ResultJSON), string(receipt.MetadataJSON), "", "", "", string(receipt.RelatedIDsJSON), receipt.Correlation,
			string(receipt.EvidenceJSON), "", "", int64(0), "", receipt.CompletedAt, receipt.CompletedAt, receipt.CompletedAt, receipt.CompletedAt,
		).Build()
	if err != nil {
		return err
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}
