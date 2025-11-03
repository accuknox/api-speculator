// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package core

import (
	"fmt"
	"strings"

	"github.com/emirpasic/gods/sets/hashset"
	"github.com/pb33f/libopenapi"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/5gsec/api-speculator/internal/apievent"
	"github.com/5gsec/api-speculator/internal/apispec"
	"github.com/5gsec/api-speculator/internal/pathtrie"
	"github.com/5gsec/api-speculator/internal/util"
)

func (m *Manager) findShadowAndZombieApi(trie pathtrie.PathTrie, events *hashset.Set, model *libopenapi.DocumentModel[v3.Document]) ([]API, []API) {
	var shadowApis []API
	var zombieApis []API

	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}
		requestPath, _ := apispec.GetPathAndQuery(event.RequestPath)

		// Skip static assets and root endpoint
		if requestPath == "/" ||
			strings.HasPrefix(requestPath, "/assets") ||
			strings.HasPrefix(requestPath, "/site") ||
			strings.HasPrefix(requestPath, "/sites") ||
			strings.HasPrefix(requestPath, "env") ||
			strings.HasSuffix(requestPath, "env") ||
			strings.HasSuffix(requestPath, "png") ||
			strings.HasSuffix(requestPath, "svg") ||
			strings.HasSuffix(requestPath, "gif") ||
			strings.HasSuffix(requestPath, "js") {
			continue
		}

		_, _, found := trie.GetPathAndValue(requestPath)
		if !found {
			if !contains(shadowApis, event) {
				shadowApis = append(shadowApis, API{
					ClusterName:   event.ClusterName,
					ServiceName:   event.ServiceName,
					RequestMethod: event.RequestMethod,
					RequestPath:   requestPath,
					Occurrences:   event.Occurrences,
					Severity:      util.SeverityCritical,
					Request:       event.Request,
					Response:      event.Response,
					StatusCode:    event.ResponseCode,
					Port:          event.Port,
				})
			}
		}

		currPathValue, found := model.Model.Paths.PathItems.Get(requestPath)
		if found {
			for operation := currPathValue.GetOperations().First(); operation != nil; operation = operation.Next() {
				if operation.Value().Deprecated != nil && *operation.Value().Deprecated {
					if !contains(zombieApis, event) {
						zombieApis = append(zombieApis, API{
							ClusterName:   event.ClusterName,
							ServiceName:   event.ServiceName,
							RequestMethod: event.RequestMethod,
							RequestPath:   requestPath,
							Occurrences:   event.Occurrences,
							Severity:      util.SeverityHigh,
							Request:       event.Request,
							Response:      event.Response,
							StatusCode:    event.ResponseCode,
							Port:          event.Port,
						})
					}
				}
			}
		}
	}

	return shadowApis, zombieApis
}

func (m *Manager) findOrphanApi(events *hashset.Set, model *libopenapi.DocumentModel[v3.Document]) []API {
	var orphanApis []API

	traffickedEndpointsWithReqMethodAndPathOnly := make(map[string]struct{}, events.Size())
	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}

		requestPath, _ := apispec.GetPathAndQuery(event.RequestPath)
		requestPath = apispec.UnifyParameterizedPathIfApplicable(requestPath, false)
		requestMethod := strings.ToUpper(event.RequestMethod)
		key := fmt.Sprintf("%v/%v", requestMethod, requestPath)

		if _, exists := traffickedEndpointsWithReqMethodAndPathOnly[key]; !exists {
			traffickedEndpointsWithReqMethodAndPathOnly[key] = struct{}{}
		}
	}

	for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
		for operations := pathItems.Value().GetOperations().First(); operations != nil; operations = operations.Next() {
			requestPath := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
			requestMethod := strings.ToUpper(operations.Key())
			key := fmt.Sprintf("%v/%v", requestMethod, requestPath)

			if _, exists := traffickedEndpointsWithReqMethodAndPathOnly[key]; !exists {
				// This spec endpoint didn't receive traffic.
				orphanApis = append(orphanApis, API{
					RequestMethod: requestMethod,
					RequestPath:   requestPath,
					Severity:      util.SeverityLow,
				})
			}
		}
	}

	return orphanApis
}

func contains(apis []API, currEvent apievent.ApiEvent) bool {
	for _, api := range apis {
		if api.RequestPath == currEvent.RequestPath &&
			api.RequestMethod == currEvent.RequestMethod &&
			api.ServiceName == currEvent.ServiceName {
			return true
		}
	}
	return false
}
