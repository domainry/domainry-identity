package contract

import authoringcontract "github.com/domainry/domainry-identity/internal/domain/authoring"

func MetadataAuthoringFieldTypes() []string {
	return []string{"boolean", "currency", "date", "datetime", "email", "integer", "long_text", "number", "percent", "phone", "relation", "select", "text", "url", "user"}
}

func metadataExpectedSchemaHashParameter() authoringcontract.CapabilityAuthoringParameter {
	return authoringcontract.CapabilityAuthoringParameter{Key: "expected_schema_hash", Type: "string", Required: true}
}

func metadataFloatPointer(value float64) *float64 { return &value }
func metadataIntPointer(value int) *int           { return &value }
