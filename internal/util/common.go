// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package util

import (
	"fmt"
	"reflect"

	"go.mongodb.org/mongo-driver/bson"
)

const (
	SeverityHigh     = "high"
	SeverityCritical = "critical"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

const (
	FindingTypeShadow = "shadow"
	FindingTypeZombie = "zombie"
	FindingTypeOrphan = "orphan"
	FindingTypeActive = "active"
)

// IsNil checks if the given interface is nil or a nil pointer.
func IsNil(a any) bool {
	return a == nil || (reflect.ValueOf(a).Kind() == reflect.Ptr && reflect.ValueOf(a).IsNil())
}

// ToInt: attempt to convert various numeric types to int
func ToInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float32:
		return int(t)
	case float64:
		return int(t)
	case uint:
		return int(t)
	case uint32:
		return int(t)
	case uint64:
		return int(t)
	case string:
		var n int
		_, err := fmt.Sscanf(t, "%d", &n)
		if err == nil {
			return n
		}
		return 0
	default:
		return 0
	}
}

// ToString: convert to string safely
func ToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}

// ToBsonM: assert to bson.M (map)
func ToBsonM(v interface{}) bson.M {
	if v == nil {
		return nil
	}
	if m, ok := v.(bson.M); ok {
		return m
	}
	//nested documents can be map[string]interface{} as well
	if m2, ok := v.(map[string]interface{}); ok {
		out := bson.M{}
		for k, val := range m2 {
			out[k] = val
		}
		return out
	}
	return nil
}
