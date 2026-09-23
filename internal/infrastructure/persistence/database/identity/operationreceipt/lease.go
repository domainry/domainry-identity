package operationreceipt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/domainry/domainry-foundation/idempotency"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
)

const (
	StatusStarted   = "started"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

type Leased struct {
	ID                 string
	WorkspaceID        string
	ActionKey          string
	ResourceType       string
	ResourceID         string
	IdempotencyKey     string
	RequestFingerprint string
	RequestedBy        string
	Status             string
	ResultJSON         json.RawMessage
	LeaseOwner         string
	LeaseExpiresAt     string
	FencingToken       int64
	ErrorCode          string
	ExpiresAt          string
	CreatedAt          string
	UpdatedAt          string
}

type Started struct {
	Leased
	Owner          string
	Kind           string
	Reason         string
	Reference      string
	MetadataJSON   json.RawMessage
	RelatedIDsJSON json.RawMessage
	EvidenceJSON   json.RawMessage
}

type Reclaim struct {
	WorkspaceID        string
	ID                 string
	RequestFingerprint string
	LeaseOwner         string
	LeaseExpiresAt     string
	ExpectedToken      int64
	ExpiredAt          string
	UpdatedAt          string
}

type Completion struct {
	WorkspaceID  string
	ID           string
	LeaseOwner   string
	FencingToken int64
	Status       string
	ResultJSON   json.RawMessage
	ErrorCode    string
	ExpiresAt    string
	CompletedAt  string
}

func InsertStarted(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Started) error {
	value.Status = StatusStarted
	for _, field := range []string{
		value.ID, value.WorkspaceID, value.Owner, value.Kind, value.ActionKey, value.ResourceType,
		value.IdempotencyKey, value.RequestFingerprint, value.RequestedBy, value.Reason,
		value.LeaseOwner, value.LeaseExpiresAt, value.CreatedAt, value.UpdatedAt,
	} {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("identity shared leased operation fields are required")
		}
	}
	if value.FencingToken <= 0 {
		return fmt.Errorf("identity shared leased operation fencing token is invalid")
	}
	if len(value.ResultJSON) == 0 {
		value.ResultJSON = json.RawMessage(`{}`)
	}
	if len(value.MetadataJSON) == 0 {
		value.MetadataJSON = json.RawMessage(`{}`)
	}
	if len(value.RelatedIDsJSON) == 0 {
		value.RelatedIDsJSON = json.RawMessage(`[]`)
	}
	if len(value.EvidenceJSON) == 0 {
		value.EvidenceJSON = json.RawMessage(`[]`)
	}
	if !json.Valid(value.ResultJSON) || !json.Valid(value.MetadataJSON) || !json.Valid(value.RelatedIDsJSON) || !json.Valid(value.EvidenceJSON) {
		return fmt.Errorf("identity shared leased operation JSON is invalid")
	}
	statement, arguments, err := query.NewWorkspaceInsertBuilder(renderer, Table, strings.TrimSpace(value.WorkspaceID)).
		Columns(
			"id", "system_purpose", "owner", "kind", "action_key", "parent_id", "resource_type", "resource_id",
			"idempotency_key", "request_fingerprint", "requested_by", "reason", "reference", "status", "status_url",
			"result_json", "metadata_json", "error_code", "failure_class", "next_action", "related_ids_json", "correlation",
			"evidence_json", "lease_owner", "lease_expires_at", "fencing_token", "expires_at", "created_at", "started_at",
			"finished_at", "updated_at",
		).
		Values(
			value.ID, "", value.Owner, value.Kind, value.ActionKey, "", value.ResourceType, value.ResourceID,
			value.IdempotencyKey, value.RequestFingerprint, value.RequestedBy, value.Reason, value.Reference, StatusStarted, "",
			string(value.ResultJSON), string(value.MetadataJSON), "", "", "", string(value.RelatedIDsJSON), "",
			string(value.EvidenceJSON), value.LeaseOwner, value.LeaseExpiresAt, value.FencingToken, value.ExpiresAt,
			value.CreatedAt, value.CreatedAt, "", value.UpdatedAt,
		).Build()
	if err != nil {
		return err
	}
	_, err = execer.ExecContext(ctx, statement, arguments...)
	return err
}

func LoadLeasedByKey(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, idempotencyKey string) (Leased, bool, error) {
	predicate := query.And(
		query.Equal("system_purpose", ""), query.Equal("owner", strings.TrimSpace(owner)),
		query.Equal("kind", strings.TrimSpace(kind)), query.Equal("idempotency_key", strings.TrimSpace(idempotencyKey)),
	)
	return loadLeased(ctx, queryer, renderer, workspaceID, predicate)
}

func LoadLeasedByID(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, id string) (Leased, bool, error) {
	predicate := query.And(
		query.Equal("system_purpose", ""), query.Equal("owner", strings.TrimSpace(owner)),
		query.Equal("kind", strings.TrimSpace(kind)), query.Equal("id", strings.TrimSpace(id)),
	)
	return loadLeased(ctx, queryer, renderer, workspaceID, predicate)
}

func ReclaimStarted(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Reclaim) (bool, error) {
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(renderer, Table, strings.TrimSpace(value.WorkspaceID)).
		Set("status", StatusStarted).Set("lease_owner", strings.TrimSpace(value.LeaseOwner)).
		Set("lease_expires_at", strings.TrimSpace(value.LeaseExpiresAt)).
		SetExpression("fencing_token", query.Add(query.Column("fencing_token"), query.Value(1))).
		Set("started_at", strings.TrimSpace(value.UpdatedAt)).Set("updated_at", strings.TrimSpace(value.UpdatedAt)).
		Where(query.And(
			query.Equal("id", strings.TrimSpace(value.ID)), query.Equal("request_fingerprint", strings.TrimSpace(value.RequestFingerprint)),
			query.Equal("status", StatusStarted), query.Equal("fencing_token", value.ExpectedToken),
			query.LessThanOrEqual("lease_expires_at", strings.TrimSpace(value.ExpiredAt)),
		)).Build()
	if err != nil {
		return false, err
	}
	result, err := execer.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func CompleteLeased(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Completion) (bool, error) {
	if value.Status != StatusSucceeded && value.Status != StatusFailed {
		return false, fmt.Errorf("identity shared leased operation completion status is invalid")
	}
	if !json.Valid(value.ResultJSON) {
		return false, fmt.Errorf("identity shared leased operation result is invalid")
	}
	failureClass := ""
	if value.Status == StatusFailed {
		failureClass = "terminal"
	}
	statement, arguments, err := query.NewWorkspaceUpdateBuilder(renderer, Table, strings.TrimSpace(value.WorkspaceID)).
		Set("status", value.Status).Set("result_json", string(value.ResultJSON)).Set("error_code", strings.TrimSpace(value.ErrorCode)).
		Set("failure_class", failureClass).Set("expires_at", strings.TrimSpace(value.ExpiresAt)).
		Set("finished_at", strings.TrimSpace(value.CompletedAt)).Set("updated_at", strings.TrimSpace(value.CompletedAt)).
		Where(query.And(
			query.Equal("id", strings.TrimSpace(value.ID)), query.Equal("lease_owner", strings.TrimSpace(value.LeaseOwner)),
			query.Equal("fencing_token", value.FencingToken), query.Equal("status", StatusStarted),
		)).Build()
	if err != nil {
		return false, err
	}
	result, err := execer.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

func IdempotencyStatus(status string) (idempotency.Status, error) {
	switch strings.TrimSpace(status) {
	case StatusStarted:
		return idempotency.StatusProcessing, nil
	case StatusSucceeded:
		return idempotency.StatusSucceeded, nil
	case StatusFailed:
		return idempotency.StatusFailedTerminal, nil
	default:
		return "", fmt.Errorf("identity shared leased operation status %q is invalid", status)
	}
}

func OperationStatus(status idempotency.Status) (string, error) {
	switch status {
	case idempotency.StatusProcessing:
		return StatusStarted, nil
	case idempotency.StatusSucceeded:
		return StatusSucceeded, nil
	case idempotency.StatusFailedTerminal:
		return StatusFailed, nil
	default:
		return "", fmt.Errorf("identity idempotency status %q has no shared Operations state", status)
	}
}

func loadLeased(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID string, predicate query.Predicate) (Leased, bool, error) {
	statement, arguments, err := query.NewWorkspaceSelectBuilder(renderer, Table, strings.TrimSpace(workspaceID)).
		Columns(
			"id", "workspace_id", "action_key", "resource_type", "resource_id", "idempotency_key", "request_fingerprint",
			"requested_by", "status", "result_json", "lease_owner", "lease_expires_at", "fencing_token", "error_code",
			"expires_at", "created_at", "updated_at",
		).Where(predicate).Limit(1).Build()
	if err != nil {
		return Leased{}, false, err
	}
	var value Leased
	var resultJSON string
	err = queryer.QueryRowContext(ctx, statement, arguments...).Scan(
		&value.ID, &value.WorkspaceID, &value.ActionKey, &value.ResourceType, &value.ResourceID, &value.IdempotencyKey,
		&value.RequestFingerprint, &value.RequestedBy, &value.Status, &resultJSON, &value.LeaseOwner, &value.LeaseExpiresAt,
		&value.FencingToken, &value.ErrorCode, &value.ExpiresAt, &value.CreatedAt, &value.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Leased{}, false, nil
	}
	if err != nil {
		return Leased{}, false, err
	}
	value.ResultJSON = json.RawMessage(resultJSON)
	if !json.Valid(value.ResultJSON) {
		return Leased{}, false, fmt.Errorf("identity shared leased operation result is invalid")
	}
	if _, err := IdempotencyStatus(value.Status); err != nil {
		return Leased{}, false, err
	}
	return value, true, nil
}
