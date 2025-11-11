package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/emirpasic/gods/sets/hashset"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/5gsec/api-speculator/internal/apievent"
	"github.com/5gsec/api-speculator/internal/util"
)

// findApiOperationDocuments fetches API documents based on collectionName, optional clusterId,
// and optional collectionCriteria. Returns a set of unique apievent.
func (m *Manager) findApiOperationDocuments(eventCollectionName, apiCollectionName string, clusterId int, collectionNames, endpoints []string) (*hashset.Set, error) {
	filter := bson.D{{Key: "operation", Value: "Api"}}
	if clusterId != 0 {
		filter = append(filter, bson.E{Key: "cluster_id", Value: clusterId})
	}

	// if apiCollectionName and nameList are provided, fetch criteria and build filter
	if apiCollectionName != "" && len(collectionNames) > 0 {
		criteriaMap, err := m.GetCriteriaByCollections(m.Ctx, apiCollectionName, collectionNames)
		if err != nil {
			m.Logger.Errorf("failed to get criteria by collections: %v", err)
			return nil, fmt.Errorf("failed to get criteria by collections: %w", err)
		}

		var allCriteria []FilterCriteria
		for _, criteria := range criteriaMap {
			allCriteria = append(allCriteria, criteria...)
		}

		if len(allCriteria) > 0 {
			criteriaFilter, err := buildMongoFilterCriteria(allCriteria)
			if err != nil {
				m.Logger.Errorf("failed to build mongo query for collection filter criteria: %v", err)
				return nil, fmt.Errorf("failed to build mongo query for collection filter criteria: %w", err)
			}
			if len(criteriaFilter) > 0 {
				firstKey := criteriaFilter[0].Key
				if strings.HasPrefix(firstKey, "$") {
					filter = append(filter, bson.E{Key: firstKey, Value: criteriaFilter[0].Value})
				} else {
					filter = append(filter, bson.E{Key: "$and", Value: bson.A{criteriaFilter}})
				}
			}
		}
	}

	if len(endpoints) > 0 {
		filter = append(filter, bson.E{Key: "api_event.http.request.path", Value: bson.M{"$in": endpoints}})
	}

	projection := bson.D{
		{Key: "_id", Value: 0},
		{Key: "cluster_name", Value: 1},
		{Key: "api_event.http.request", Value: 1},
		{Key: "api_event.http.response", Value: 1},
		{Key: "api_event.network.destination.port", Value: 1},
		{Key: "api_event.count", Value: 1},
	}

	cursor, err := m.DBHandler.Database.Collection(eventCollectionName).Find(
		m.Ctx, filter, &options.FindOptions{Projection: projection},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to find documents: %w", err)
	}
	defer func() {
		if cerr := cursor.Close(m.Ctx); cerr != nil {
			m.Logger.Warnf("failed to close cursor: %v", cerr)
		}
	}()

	apiEvents := hashset.New()

	for cursor.Next(m.Ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			m.Logger.Warnf("failed to decode document: %v", err)
			continue
		}

		clusterName := util.ToString(doc["cluster_name"])

		apiEvent := util.ToBsonM(doc["api_event"])
		if apiEvent == nil {
			continue
		}

		httpEvent := util.ToBsonM(apiEvent["http"])
		networkEvent := util.ToBsonM(apiEvent["network"])

		req := util.ToBsonM(httpEvent["request"])
		resp := util.ToBsonM(httpEvent["response"])

		responseCode := util.ToInt(resp["status_code"])
		if responseCode == 0 {
			continue
		}

		// Extract port
		port := 0
		if networkEvent != nil {
			if dest := util.ToBsonM(networkEvent["destination"]); dest != nil {
				port = util.ToInt(dest["port"])
			}
		}

		// Extract headers → serviceName
		serviceName := ""
		if req != nil {
			if headers := util.ToBsonM(req["headers"]); headers != nil {
				if v := util.ToString(headers[":authority"]); v != "" {
					serviceName = v
				} else if v := util.ToString(headers["host"]); v != "" {
					serviceName = v
				}
			}
		}

		requestMethod := util.ToString(req["method"])
		requestPath := util.ToString(req["path"])
		var requestBody interface{}
		if req != nil {
			requestBody = req["body"]
		}

		var responseBody interface{}
		if resp != nil {
			responseBody = resp["body"]
		}

		occurrences := util.ToInt(apiEvent["count"])

		apiEvents.Add(apievent.ApiEvent{
			ClusterName:   clusterName,
			ServiceName:   serviceName,
			RequestMethod: requestMethod,
			RequestPath:   requestPath,
			ResponseCode:  responseCode,
			Occurrences:   occurrences,
			Port:          port,
			Request:       requestBody,
			Response:      responseBody,
		})
	}

	if err := cursor.Err(); err != nil {
		return apiEvents, fmt.Errorf("cursor iteration error: %w", err)
	}

	return apiEvents, nil
}

// FilterCriteria defines a condition and operator for Mongo query filtering.
type FilterCriteria struct {
	Operator  string    `bson:"operator,omitempty" json:"operator,omitempty"`
	Condition Condition `bson:"condition,omitempty" json:"condition,omitempty"`
}

// Condition represents a filter condition containing a field and its value.
type Condition struct {
	Field string          `bson:"field,omitempty" json:"field,omitempty"`
	Value StringOperators `bson:"value,omitempty" json:"value,omitempty"`
}

// StringOperators represents string-based comparison filters.
type StringOperators struct {
	Eq    []string `json:"eq,omitempty" bson:"eq,omitempty"`
	Neq   []string `json:"neq,omitempty" bson:"neq,omitempty"`
	RegEx []string `json:"regex,omitempty" bson:"regex,omitempty"`
}

// FieldMeta contains metadata describing a MongoDB field mapping.
type FieldMeta struct {
	DisplayName map[string]string
	BsonKey     string
	UnwindPath  string
	DefaultSort string
	FieldType   string // e.g., "string", "number", "boolean"
}

// fieldMetadata maps logical field names to BSON key paths and metadata.
func fieldMetadata(field string) (*FieldMeta, error) {
	fieldMap := map[string]*FieldMeta{
		"api_type":            {BsonKey: "api_event.metadata.api_type", FieldType: "string"},
		"auth_type":           {BsonKey: "api_event.metadata.is_authenticated", DisplayName: map[string]string{"true": "Authenticated", "false": "Non-authenticated"}, FieldType: "boolean"},
		"hostname":            {BsonKey: "api_event.http.request.hostname", FieldType: "string"},
		"method":              {BsonKey: "api_event.http.request.method", FieldType: "string"},
		"path":                {BsonKey: "api_event.http.request.path", FieldType: "string"},
		"response_code":       {BsonKey: "api_event.http.response.status_code", FieldType: "number"},
		"access_type":         {BsonKey: "api_event.metadata.access_type", FieldType: "string"},
		"count":               {BsonKey: "api_event.count"},
		"destination_ip":      {BsonKey: "destination", FieldType: "string"},
		"destination_name":    {BsonKey: "api_event.network.destination.metadata.name", FieldType: "string"},
		"destination_type":    {BsonKey: "api_event.network.destination.type", FieldType: "string"},
		"risk_score":          {BsonKey: "api_event.overall_risk_score", FieldType: "number"},
		"severity":            {BsonKey: "api_event.overall_severity", FieldType: "number"},
		"sensitive_data_type": {UnwindPath: "api_event.sensitive_data", BsonKey: "api_event.sensitive_data.name", FieldType: "string"},
	}

	if details, ok := fieldMap[field]; ok {
		return details, nil
	}
	return nil, fmt.Errorf("unknown group_by key: %s", field)
}

// buildMongoFilterCriteria converts a list of FilterCriteria into a MongoDB filter (bson.D).
func buildMongoFilterCriteria(filterCriteria []FilterCriteria) (bson.D, error) {
	if len(filterCriteria) == 0 {
		return bson.D{}, fmt.Errorf("filter criteria is empty")
	}

	expr := bson.D{}

	first := filterCriteria[0]
	fieldMeta, err := fieldMetadata(first.Condition.Field)
	if err != nil {
		return bson.D{}, fmt.Errorf("error getting bson key for field '%s': %v", first.Condition.Field, err)
	}
	if err := addToFilter(&expr, fieldMeta.BsonKey, first.Condition.Value); err != nil {
		return bson.D{}, fmt.Errorf("error creating bson object for field '%s': %v", fieldMeta.BsonKey, err)
	}

	for i := 1; i < len(filterCriteria); i++ {
		next := filterCriteria[i]
		nextExpr := bson.D{}
		fieldMeta, err := fieldMetadata(next.Condition.Field)
		if err != nil {
			return bson.D{}, fmt.Errorf("error getting bson key for field '%s': %v", next.Condition.Field, err)
		}
		if err := addToFilter(&nextExpr, fieldMeta.BsonKey, next.Condition.Value); err != nil {
			return bson.D{}, fmt.Errorf("error creating bson object for field '%s': %v", fieldMeta.BsonKey, err)
		}

		op := strings.ToUpper(next.Operator)
		switch op {
		case "OR":
			expr = bson.D{{Key: "$or", Value: bson.A{expr, nextExpr}}}
		case "AND":
			expr = bson.D{{Key: "$and", Value: bson.A{expr, nextExpr}}}
		default:
			return bson.D{}, fmt.Errorf("unknown operator '%s' in filter criteria", op)
		}
	}

	return expr, nil
}

// appendStringFilter adds string comparison filters to the provided bson.D.
func appendStringFilter(key string, op StringOperators, filters *bson.D) {
	if !validateStringOperator(op) {
		return
	}

	switch {
	case len(op.Eq) > 0:
		*filters = append(*filters, bson.E{Key: key, Value: bson.D{{Key: "$in", Value: op.Eq}}})
	case len(op.Neq) > 0:
		*filters = append(*filters, bson.E{Key: key, Value: bson.D{{Key: "$nin", Value: op.Neq}}})
	case len(op.RegEx) > 0:
		*filters = append(*filters, bson.E{Key: key, Value: bson.D{{Key: "$regex", Value: primitive.Regex{Pattern: op.RegEx[0], Options: "i"}}}})
	}
}

// validateStringOperator ensures only one type of string operator is applied.
func validateStringOperator(filter StringOperators) bool {
	if len(filter.Eq) != 0 && len(filter.Neq) != 0 && len(filter.RegEx) != 0 {
		return false
	}
	if len(filter.Eq) != 0 && (len(filter.Neq) != 0 || len(filter.RegEx) != 0) {
		return false
	}
	if len(filter.Eq) == 0 && (len(filter.Neq) != 0 && len(filter.RegEx) != 0) {
		return false
	}
	return true
}

// addToFilter appends a filter condition to the provided bson.D based on field type.
func addToFilter(filter *bson.D, fieldName string, fieldValue interface{}) error {
	switch v := fieldValue.(type) {
	case StringOperators:
		if !validateStringOperator(v) {
			return fmt.Errorf("invalid string operator for field '%s': %v", fieldName, v)
		}
		appendStringFilter(fieldName, v, filter)
	default:
		return fmt.Errorf("unsupported field value type '%T' for field '%s'", v, fieldName)
	}
	return nil
}

// GetCriteriaByCollections fetches the "criteria" field for the given api_collection names.
// It returns a map of collectionName → []FilterCriteria.
func (m *Manager) GetCriteriaByCollections(ctx context.Context, apiCollectionName string, names []string) (map[string][]FilterCriteria, error) {
	if apiCollectionName == "" {
		return nil, fmt.Errorf("apiCollectionName is empty")
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no collection names provided")
	}

	filter := bson.M{
		"name": bson.M{"$in": names},
	}

	proj := bson.M{"name": 1, "criteria": 1}
	opts := options.Find().SetProjection(proj)

	cursor, err := m.DBHandler.Database.Collection(apiCollectionName).Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to find collections in %q: %w", apiCollectionName, err)
	}
	defer cursor.Close(ctx)

	result := make(map[string][]FilterCriteria, len(names))
	for cursor.Next(ctx) {
		var doc struct {
			Name     string           `bson:"name"`
			Criteria []FilterCriteria `bson:"criteria"`
		}
		if err := cursor.Decode(&doc); err != nil {
			return nil, fmt.Errorf("failed to decode collection document: %w", err)
		}
		if doc.Name == "" {
			continue
		}
		result[doc.Name] = doc.Criteria
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return result, nil
}
