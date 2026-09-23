package operationreceipt

import (
	"context"
	"encoding/json"

	sharedoperation "github.com/domainry/domainry-foundation/operation"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

const Table = sharedoperation.TableName

type Queryer = sharedoperation.Queryer
type Execer = sharedoperation.Execer
type Receipt = sharedoperation.SucceededReceipt
type Succeeded = sharedoperation.SucceededRecord

func Load(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, idempotencyKey string) (Receipt, bool, error) {
	return sharedoperation.LoadSucceeded(ctx, queryer, renderer, workspaceID, owner, kind, idempotencyKey)
}

func LoadReferenced(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, idempotencyKey string) (Receipt, bool, error) {
	return sharedoperation.LoadSucceededReferenced(ctx, queryer, renderer, workspaceID, owner, kind, idempotencyKey)
}

func LoadByID(ctx context.Context, queryer Queryer, renderer ormdialect.Renderer, workspaceID, owner, kind, id string) (Receipt, bool, error) {
	return sharedoperation.LoadSucceededByID(ctx, queryer, renderer, workspaceID, owner, kind, id)
}

func UpdateSucceededResult(ctx context.Context, execer Execer, renderer ormdialect.Renderer, workspaceID, owner, kind, id string, previous, next json.RawMessage, updatedAt string) (bool, error) {
	return sharedoperation.UpdateSucceededResult(ctx, execer, renderer, workspaceID, owner, kind, id, previous, next, updatedAt)
}

func InsertSucceeded(ctx context.Context, execer Execer, renderer ormdialect.Renderer, value Succeeded) error {
	return sharedoperation.InsertSucceeded(ctx, execer, renderer, value)
}
