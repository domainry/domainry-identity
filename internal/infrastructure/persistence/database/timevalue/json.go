package timevalue

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

var jsonTimeType = reflect.TypeOf(time.Time{})

func MarshalJSON(value any) ([]byte, error) {
	return marshalJSON(value, false)
}

func MarshalJSONIndent(value any) ([]byte, error) {
	return marshalJSON(value, true)
}

func marshalJSON(value any, indent bool) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	document, err := jsonDocument(raw)
	if err != nil {
		return nil, err
	}
	document = encodeJSONTimes(reflect.ValueOf(value), document)
	if indent {
		return json.MarshalIndent(document, "", "  ")
	}
	return json.Marshal(document)
}

func UnmarshalJSON(raw []byte, destination any) error {
	target := reflect.TypeOf(destination)
	if target == nil || target.Kind() != reflect.Pointer {
		return fmt.Errorf("time JSON destination must be a pointer")
	}
	document, err := jsonDocument(raw)
	if err != nil {
		return err
	}
	document, err = decodeJSONTimes(target.Elem(), document)
	if err != nil {
		return err
	}
	normalized, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return json.Unmarshal(normalized, destination)
}

func jsonDocument(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	err := decoder.Decode(&document)
	return document, err
}

func encodeJSONTimes(value reflect.Value, document any) any {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return document
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return document
	}
	if value.Type() == jsonTimeType {
		instant := value.Interface().(time.Time)
		if instant.IsZero() {
			return int64(0)
		}
		return instant.UTC().UnixMilli()
	}
	switch value.Kind() {
	case reflect.Struct:
		object, ok := document.(map[string]any)
		if !ok {
			return document
		}
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if field.PkgPath != "" {
				continue
			}
			if field.Anonymous && field.Tag.Get("json") == "" {
				object, _ = encodeJSONTimes(value.Field(index), object).(map[string]any)
				continue
			}
			name, included := jsonFieldName(field)
			if child, exists := object[name]; included && exists {
				object[name] = encodeJSONTimes(value.Field(index), child)
			}
		}
		return object
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return document
		}
		items, ok := document.([]any)
		if !ok {
			return document
		}
		for index := 0; index < value.Len() && index < len(items); index++ {
			items[index] = encodeJSONTimes(value.Index(index), items[index])
		}
		return items
	case reflect.Map:
		object, ok := document.(map[string]any)
		if !ok || value.Type().Key().Kind() != reflect.String {
			return document
		}
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			if child, exists := object[key]; exists {
				object[key] = encodeJSONTimes(iterator.Value(), child)
			}
		}
	}
	return document
}

func decodeJSONTimes(target reflect.Type, document any) (any, error) {
	for target.Kind() == reflect.Pointer {
		if document == nil {
			return nil, nil
		}
		target = target.Elem()
	}
	if target == jsonTimeType {
		number, ok := document.(json.Number)
		if !ok {
			return nil, fmt.Errorf("stored time must be a Unix-millisecond number")
		}
		millis, err := number.Int64()
		if err != nil {
			return nil, err
		}
		if millis == 0 {
			return "0001-01-01T00:00:00Z", nil
		}
		return time.UnixMilli(millis).UTC().Format(time.RFC3339Nano), nil
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := document.(map[string]any)
		if !ok {
			return document, nil
		}
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			if field.PkgPath != "" {
				continue
			}
			if field.Anonymous && field.Tag.Get("json") == "" {
				normalized, err := decodeJSONTimes(field.Type, object)
				if err != nil {
					return nil, err
				}
				object, _ = normalized.(map[string]any)
				continue
			}
			name, included := jsonFieldName(field)
			child, exists := object[name]
			if !included || !exists {
				continue
			}
			normalized, err := decodeJSONTimes(field.Type, child)
			if err != nil {
				return nil, fmt.Errorf("decode stored JSON field %s: %w", name, err)
			}
			object[name] = normalized
		}
		return object, nil
	case reflect.Slice, reflect.Array:
		if target.Elem().Kind() == reflect.Uint8 {
			return document, nil
		}
		items, ok := document.([]any)
		if !ok {
			return document, nil
		}
		for index := range items {
			normalized, err := decodeJSONTimes(target.Elem(), items[index])
			if err != nil {
				return nil, err
			}
			items[index] = normalized
		}
	}
	return document, nil
}

func jsonFieldName(field reflect.StructField) (string, bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	name := strings.Split(tag, ",")[0]
	if name == "" {
		name = field.Name
	}
	return name, true
}
