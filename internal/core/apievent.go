package core

import (
	"fmt"

	"github.com/emirpasic/gods/sets/hashset"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/5gsec/api-speculator/internal/apievent"
	"github.com/5gsec/api-speculator/internal/util"
)

func (m *Manager) findDocuments(collectionName string, clusterId int) (*hashset.Set, error) {
	filter := bson.D{{Key: "operation", Value: "Api"}}
	if clusterId != 0 {
		filter = append(filter, bson.E{Key: "cluster_id", Value: clusterId})
	}

	projection := bson.D{
		{Key: "_id", Value: 0},
		{Key: "cluster_name", Value: 1},
		{Key: "api_event.http.request", Value: 1},
		{Key: "api_event.http.response", Value: 1},
		{Key: "api_event.network.destination.port", Value: 1},
		{Key: "api_event.count", Value: 1},
	}

	cursor, err := m.DBHandler.Database.Collection(collectionName).Find(
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
