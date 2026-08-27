package changeplan

import (
	"context"
	"encoding/json"
	"strings"

	auditmodel "github.com/domainry/domainry-identity/internal/domain/audit/model"
	changeplanmodel "github.com/domainry/domainry-identity/internal/domain/changeplan/model"
	changeplanprojection "github.com/domainry/domainry-identity/internal/domain/changeplan/projection"
	identitymodel "github.com/domainry/domainry-identity/internal/domain/identity/model"
	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

func (s *ChangePlanApplicationService) metadataChangePlanMutations(ctx context.Context, plan changeplanmodel.BusinessSystemChangePlan, principal identitymodel.Principal) ([]metadatamodel.MetadataDefinitionMutation, []auditmodel.AuditEvent, error) {
	items := map[string]changeplanmodel.BusinessSystemChangeItem{}
	for _, item := range plan.Items {
		items[item.ItemID] = item
	}
	mutations := []metadatamodel.MetadataDefinitionMutation{}
	audits := []auditmodel.AuditEvent{}
	for _, itemID := range plan.ReleaseOrder {
		item := items[itemID]
		if item.Operation == "noop" {
			continue
		}
		resourceType := strings.TrimSpace(item.ResourceType)
		if !businessChangePlanMetadataResourceType(resourceType) {
			return nil, nil, badRequest("backend.change_plan.apply_resource_unsupported", "item_id", item.ItemID, "resource_type", resourceType, "resource_key", item.ResourceKey)
		}
		request := metadataChangePlanRequest(plan, item)
		mutations = append(mutations, metadatamodel.MetadataDefinitionMutation{Operation: item.Operation, ResourceType: resourceType, ResourceKey: item.ResourceKey, Request: request})
		audits = append(audits, buildBusinessChangePlanAudit(plan, item, principal))
	}
	if s.runtime == nil {
		return nil, nil, internalError("validate composed Identity metadata candidate", nil)
	}
	mutations, err := s.runtime.CanonicalizeMetadataCandidate(ctx, mutations)
	if err != nil {
		return nil, nil, err
	}
	return mutations, audits, nil
}

func metadataChangePlanRequest(plan changeplanmodel.BusinessSystemChangePlan, item changeplanmodel.BusinessSystemChangeItem) metadatamodel.MetadataDefinitionUpsertRequest {
	expected := item.ExpectedResourceHash
	if item.Operation == "create" {
		expected = ""
	}
	after := businessChangeJSONMap(item.After)
	objectKey := strings.TrimSpace(stringValue(after["object_key"]))
	if objectKey == "" && item.ResourceType == "field" {
		objectKey = strings.SplitN(item.ResourceKey, ".", 2)[0]
	}
	name := strings.TrimSpace(stringValue(after["name"]))
	return metadatamodel.MetadataDefinitionUpsertRequest{ObjectKey: objectKey, Name: name, SourceKind: "admin", SourceID: plan.PlanID, ExpectedSchemaHash: &expected, Payload: append(json.RawMessage(nil), item.After...)}
}

func businessChangePlanMetadataResourceType(resourceType string) bool {
	for _, candidate := range businessChangePlanMetadataResourceTypes() {
		if strings.TrimSpace(resourceType) == candidate {
			return true
		}
	}
	return false
}

func businessChangePlanMetadataResourceTypes() []string {
	return []string{"object", "field", "validation", "view", "action", "role", "identity_profile_binding"}
}

func buildBusinessChangePlanAudit(plan changeplanmodel.BusinessSystemChangePlan, item changeplanmodel.BusinessSystemChangeItem, principal identitymodel.Principal) auditmodel.AuditEvent {
	metadata := map[string]any{"plan_id": plan.PlanID, "business_reason": plan.BusinessReason, "operation": item.Operation, "change_kind": item.ChangeKind, "risk_level": item.RiskLevel, "capability_key": item.CapabilityKey, "validation_methods": item.ValidationMethods, "snapshot_hash": plan.SnapshotHash, "reference_graph_hash": plan.ReferenceGraphHash, "contract_version": plan.AuthoringContractVersion, "reviewed": plan.Reviewed, "reviewed_by": plan.ReviewedBy, "rollback_method": item.RollbackMethod}
	return buildAuditEvent("identity_change_plan.item_applied", item.ResourceType, item.ResourceKey, principal, changeplanprojection.ChangePlanBusinessSummary(item), businessChangeJSONMap(item.Before), businessChangeJSONMap(item.After), metadata)
}

func businessChangeJSONMap(payload json.RawMessage) map[string]any {
	values := map[string]any{}
	_ = json.Unmarshal(payload, &values)
	return values
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
