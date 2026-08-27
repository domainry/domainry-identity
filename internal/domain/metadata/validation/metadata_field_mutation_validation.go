package validation

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	definitionmodel "github.com/domainry/domainry-identity/internal/domain/definition/model"
	identitycontract "github.com/domainry/domainry-identity/internal/domain/identity/contract"

	"regexp"
	"strings"

	metadatamodel "github.com/domainry/domainry-identity/internal/domain/metadata/model"
)

// MetadataNormalizeFieldMutation owns pure field-definition normalization and
// evaluates compatibility against a caller-provided record snapshot.
func MetadataNormalizeFieldMutation(request metadatamodel.MetadataDefinitionUpsertRequest, objects []definitionmodel.ObjectSchema, allowedFieldTypes []string, existingRecordCount int) (metadatamodel.MetadataDefinitionUpsertRequest, error) {
	var field definitionmodel.FieldSchema
	if err := json.Unmarshal(request.Payload, &field); err != nil {
		return request, badRequest("backend.metadata.field_definition_invalid")
	}
	if !containsFieldType(allowedFieldTypes, field.Type) {
		return request, badRequest("backend.metadata.field_type_invalid", "field", field.Key, "type", field.Type, "allowed", strings.Join(allowedFieldTypes, ","))
	}
	if err := metadataValidateLocalizedField(field); err != nil {
		return request, badRequest("backend.metadata.localized_field_invalid", "field", field.Key, "detail", err.Error())
	}
	if strings.TrimSpace(field.Type) == "currency" {
		config, err := metadataNormalizeDecimalConfig(field.Config)
		if err != nil {
			return request, badRequest(metadataDecimalErrorCode(err), "field", field.Key)
		}
		if field.Config == nil {
			field.Config = map[string]any{}
		}
		field.Config["precision"] = config.Precision
		field.Config["scale"] = config.Scale
		field.Config["rounding_mode"] = config.RoundingMode
		field.Config["currency_code"] = config.CurrencyCode
		payload, _ := json.Marshal(field)
		request.Payload = payload
	}
	objectKey := strings.TrimSpace(request.ObjectKey)
	if objectKey == "" && field.Config != nil {
		objectKey = cleanFieldValue(field.Config["_definition_object_key"])
	}
	objectMap := make(map[string]definitionmodel.ObjectSchema, len(objects))
	for _, object := range objects {
		objectMap[strings.TrimSpace(object.Key)] = object
	}
	object, exists := objectMap[objectKey]
	if !exists {
		return request, badRequest("backend.metadata.field_object_not_found", "object", objectKey)
	}
	if strings.TrimSpace(field.Type) == "relation" {
		if field.Config == nil {
			field.Config = map[string]any{}
		}
		target := fieldRelationTarget(field)
		if target == "" {
			return request, badRequest("backend.metadata.relation_target_required", "object", objectKey, "field", field.Key)
		}
		if _, found := objectMap[target]; !found && !identitycontract.IsFoundationObjectKey(target) {
			return request, badRequest("backend.metadata.relation_target_not_found", "object", objectKey, "field", field.Key, "target", target)
		}
		cardinality := defaultFieldValue(field.Config["cardinality"], "many_to_one")
		if cardinality != "many_to_one" && cardinality != "one_to_one" {
			return request, badRequest("backend.metadata.relation_cardinality_invalid", "object", objectKey, "field", field.Key, "cardinality", cardinality)
		}
		onDelete := defaultFieldValue(field.Config["on_delete"], "restrict")
		switch onDelete {
		case "restrict", "set_null", "cascade":
		default:
			return request, badRequest("backend.metadata.relation_on_delete_invalid", "object", objectKey, "field", field.Key, "on_delete", onDelete)
		}
		if onDelete == "set_null" && field.Required {
			return request, badRequest("backend.metadata.relation_set_null_required", "object", objectKey, "field", field.Key)
		}
		inverseName := cleanFieldValue(field.Config["inverse_name"])
		if inverseName != "" && !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(inverseName) {
			return request, badRequest("backend.metadata.relation_inverse_name_invalid", "object", objectKey, "field", field.Key, "inverse_name", inverseName)
		}
		field.Validation.Target = target
		field.Config["target"] = target
		field.Config["cardinality"] = cardinality
		field.Config["on_delete"] = onDelete
		field.Config["inverse_name"] = inverseName
		if _, present := field.Config["indexed"]; !present {
			field.Config["indexed"] = true
		}
		field.Unique = cardinality == "one_to_one"
		if field.Unique {
			field.Config["indexed"] = true
		}
		// field was decoded from JSON above, so its interface values are JSON-safe.
		payload, _ := json.Marshal(field)
		request.Payload = payload
	}
	var existing *definitionmodel.FieldSchema
	for _, candidate := range object.Fields {
		if strings.TrimSpace(candidate.Key) == strings.TrimSpace(field.Key) {
			copy := candidate
			existing = &copy
			break
		}
	}
	if !field.Required || field.Default != nil || field.DefaultValue != nil || (existing != nil && existing.Required) || existingRecordCount == 0 {
		return request, nil
	}
	return request, badRequest("backend.metadata.required_field_default_required", "object", objectKey, "field", field.Key, "records", fmt.Sprint(existingRecordCount))
}

type metadataDecimalConfig struct {
	Precision    int
	Scale        int
	RoundingMode string
	CurrencyCode string
}

type metadataDecimalError string

func (e metadataDecimalError) Error() string { return string(e) }

func metadataNormalizeDecimalConfig(raw map[string]any) (metadataDecimalConfig, error) {
	config := metadataDecimalConfig{Precision: 19, Scale: 2, RoundingMode: "half_even", CurrencyCode: "XXX"}
	if value, exists := raw["precision"]; exists {
		parsed, ok := metadataInteger(value)
		if !ok {
			return metadataDecimalConfig{}, metadataDecimalError("backend.decimal.precision_invalid")
		}
		config.Precision = parsed
	}
	if value, exists := raw["scale"]; exists {
		parsed, ok := metadataInteger(value)
		if !ok {
			return metadataDecimalConfig{}, metadataDecimalError("backend.decimal.scale_invalid")
		}
		config.Scale = parsed
	}
	if value, exists := raw["rounding_mode"]; exists {
		config.RoundingMode = strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	}
	if value, exists := raw["currency_code"]; exists {
		config.CurrencyCode = strings.ToUpper(strings.TrimSpace(fmt.Sprint(value)))
	}
	if config.Precision < 1 || config.Precision > 38 {
		return metadataDecimalConfig{}, metadataDecimalError("backend.decimal.precision_invalid")
	}
	if config.Scale < 0 || config.Scale > config.Precision {
		return metadataDecimalConfig{}, metadataDecimalError("backend.decimal.scale_invalid")
	}
	if !map[string]bool{"half_even": true, "half_up": true, "down": true, "up": true, "floor": true, "ceiling": true}[config.RoundingMode] {
		return metadataDecimalConfig{}, metadataDecimalError("backend.decimal.rounding_mode_invalid")
	}
	if !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(config.CurrencyCode) {
		return metadataDecimalConfig{}, metadataDecimalError("backend.decimal.currency_code_invalid")
	}
	return config, nil
}

func metadataInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), !math.IsNaN(typed) && !math.IsInf(typed, 0) && math.Trunc(typed) == typed
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func metadataValidateLocalizedField(field definitionmodel.FieldSchema) error {
	localized := false
	if field.Config != nil {
		switch value := field.Config["localized"].(type) {
		case bool:
			localized = value
		case string:
			localized = strings.EqualFold(strings.TrimSpace(value), "true")
		}
	}
	if !localized {
		return nil
	}
	if field.Type != "text" && field.Type != "long_text" {
		return fmt.Errorf("localized field %q must use text or long_text", field.Key)
	}
	if field.Unique {
		return fmt.Errorf("localized field %q cannot be unique", field.Key)
	}
	return nil
}

func metadataDecimalErrorCode(err error) string {
	if code, ok := err.(metadataDecimalError); ok {
		return string(code)
	}
	return "backend.decimal.value_invalid"
}

func containsFieldType(allowed []string, fieldType string) bool {
	fieldType = strings.TrimSpace(fieldType)
	for _, candidate := range allowed {
		if strings.TrimSpace(candidate) == fieldType {
			return true
		}
	}
	return false
}

func fieldRelationTarget(field definitionmodel.FieldSchema) string {
	if target := strings.TrimSpace(field.Validation.Target); target != "" {
		return target
	}
	for _, key := range []string{"target", "object_key", "target_object"} {
		if target := cleanFieldValue(field.Config[key]); target != "" {
			return target
		}
	}
	return ""
}

func defaultFieldValue(value any, fallback string) string {
	if result := cleanFieldValue(value); result != "" {
		return result
	}
	return fallback
}

func cleanFieldValue(value any) string {
	result := strings.TrimSpace(fmt.Sprint(value))
	if result == "<nil>" {
		return ""
	}
	return result
}
