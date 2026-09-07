package organizationunit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeliveryContractCarriesNoCallerAuthorityOrDerivedHierarchy(t *testing.T) {
	request := DeliveryRequest{
		ContractVersion: DeliveryContractVersionV1,
		AccessToken:     "secret-token",
		IdempotencyKey:  "department-create-1",
		Organization: CreateCandidate{
			OrganizationID: "department-sales", Code: "SALES", Name: "Sales", NodeType: NodeTypeDepartment,
			ParentOrganizationID: "company", ExpectedVersion: 0,
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-token", "workspace_id", "actor_id", "path", "ancestor_ids", "depth", "status"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("serialized delivery request carries forbidden %q: %s", forbidden, payload)
		}
	}
}

func TestNodeTypeContractIsClosed(t *testing.T) {
	for _, value := range []NodeType{NodeTypeCompany, NodeTypeRegion, NodeTypeStore, NodeTypeDepartment, NodeTypeTeam, NodeTypeWarehouse} {
		if !value.Valid() {
			t.Fatalf("node type %q is not valid", value)
		}
	}
	if NodeType("division").Valid() {
		t.Fatal("unknown node type accepted")
	}
	for _, value := range []NodeType{NodeTypeRegion, NodeTypeDepartment, NodeTypeTeam, NodeTypeWarehouse} {
		if !value.ValidDeliveryChild() {
			t.Fatalf("delivery child type %q rejected", value)
		}
	}
	for _, value := range []NodeType{NodeTypeCompany, NodeTypeStore, NodeType("division")} {
		if value.ValidDeliveryChild() {
			t.Fatalf("reserved delivery child type %q accepted", value)
		}
	}
}
