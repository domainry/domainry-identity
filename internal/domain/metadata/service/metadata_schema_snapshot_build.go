package service

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func SchemaSnapshotHash(snapshot metadatamodel.MetadataSchemaSnapshot) string {
	snapshot.SchemaHash, snapshot.SnapshotVersion = "", ""
	payload, _ := json.Marshal(snapshot)
	hash := sha256.Sum256(payload)
	return fmt.Sprintf("%x", hash[:])[:16]
}

func GuardedWriteContracts(actions []definitionmodel.ActionSchema) []metadatamodel.MetadataGuardedWriteContract {
	_ = actions
	return []metadatamodel.MetadataGuardedWriteContract{}
}
