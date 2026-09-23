package metadata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sharedoperation "github.com/domainry/domainry-foundation/operation"
)

const (
	manifestSeedCheckpointOwner = "identity"
	manifestSeedCheckpointKind  = "identity.manifest_seed_checkpoint"
)

type manifestSeedCheckpointResult struct {
	Version string `json:"version"`
}

func (s MetadataStore) ManifestIdentitySeedSyncedVersion(ctx context.Context) (string, error) {
	workspaceID, err := s.manifestSeedCheckpointWorkspace(ctx)
	if err != nil {
		return "", err
	}
	receipt, found, err := sharedoperation.LoadSucceededByID(
		ctx, s.database(), s.store.SQLRenderer, workspaceID,
		manifestSeedCheckpointOwner, manifestSeedCheckpointKind, manifestSeedCheckpointID(workspaceID),
	)
	if err != nil || !found {
		return "", err
	}
	var result manifestSeedCheckpointResult
	if err := json.Unmarshal(receipt.ResultJSON, &result); err != nil {
		return "", fmt.Errorf("decode Identity manifest seed checkpoint: %w", err)
	}
	return strings.TrimSpace(result.Version), nil
}

func (s MetadataStore) SetManifestIdentitySeedSyncedVersion(ctx context.Context, version string) error {
	workspaceID, err := s.manifestSeedCheckpointWorkspace(ctx)
	if err != nil {
		return err
	}
	next, err := json.Marshal(manifestSeedCheckpointResult{Version: strings.TrimSpace(version)})
	if err != nil {
		return err
	}
	id := manifestSeedCheckpointID(workspaceID)
	for attempt := 0; attempt < 3; attempt++ {
		receipt, found, readErr := sharedoperation.LoadSucceededByID(
			ctx, s.database(), s.store.SQLRenderer, workspaceID,
			manifestSeedCheckpointOwner, manifestSeedCheckpointKind, id,
		)
		if readErr != nil {
			return readErr
		}
		if found {
			if bytes.Equal(receipt.ResultJSON, next) {
				return nil
			}
			updated, updateErr := sharedoperation.UpdateSucceededResult(
				ctx, s.database(), s.store.SQLRenderer, workspaceID,
				manifestSeedCheckpointOwner, manifestSeedCheckpointKind, id,
				receipt.ResultJSON, next, time.Now().UTC().Format(time.RFC3339Nano),
			)
			if updateErr != nil {
				return updateErr
			}
			if updated {
				return nil
			}
			continue
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		insertErr := sharedoperation.InsertSucceeded(ctx, s.database(), s.store.SQLRenderer, sharedoperation.SucceededRecord{
			ID: id, WorkspaceID: workspaceID, Owner: manifestSeedCheckpointOwner, Kind: manifestSeedCheckpointKind,
			ActionKey: "identity.manifest_seed.sync", ResourceType: "identity_manifest", ResourceID: workspaceID,
			IdempotencyKey: "identity-manifest-seed-checkpoint", RequestFingerprint: "identity-manifest-seed-checkpoint-v1",
			RequestedBy: "identity.manifest_seed", Reason: "record the applied Identity manifest seed",
			ResultJSON: next, CompletedAt: now,
		})
		if insertErr == nil {
			return nil
		}
	}
	return fmt.Errorf("Identity manifest seed checkpoint changed concurrently")
}

func (s MetadataStore) manifestSeedCheckpointWorkspace(ctx context.Context) (string, error) {
	workspaceID := strings.TrimSpace(s.tenantWorkspaceID(ctx))
	if workspaceID == "" {
		return "", fmt.Errorf("Identity manifest seed checkpoint workspace is required")
	}
	return workspaceID, nil
}

func manifestSeedCheckpointID(workspaceID string) string {
	digest := sha256.Sum256([]byte("identity-manifest-seed-checkpoint\x00" + strings.TrimSpace(workspaceID)))
	return "identity-manifest-seed-checkpoint:" + hex.EncodeToString(digest[:16])
}
