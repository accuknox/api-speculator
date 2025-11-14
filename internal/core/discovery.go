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
	"github.com/5gsec/api-speculator/internal/util"
)

// findShadowAndZombieApis finds shadow (traffic not in trie/spec) and zombie (deprecated in spec but seen in traffic) APIs.
func (m *Manager) findShadowAndZombieApis(events *hashset.Set, modelsMap map[string]*libopenapi.DocumentModel[v3.Document]) ([]API, []API) {
	var shadowApis []API
	var zombieApis []API

	if events == nil || len(modelsMap) == 0 {
		return shadowApis, zombieApis
	}

	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}

		requestPathRaw, _ := apispec.GetPathAndQuery(event.RequestPath)
		normalizedPath := apispec.UnifyParameterizedPathIfApplicable(requestPathRaw, false)
		methodLower := strings.ToLower(event.RequestMethod)

		if requestPathRaw == "/" ||
			strings.HasPrefix(requestPathRaw, "/assets") ||
			strings.HasPrefix(requestPathRaw, "/site") ||
			strings.HasPrefix(requestPathRaw, "/sites") ||
			strings.HasPrefix(requestPathRaw, "env") ||
			strings.HasSuffix(requestPathRaw, "env") ||
			strings.HasSuffix(requestPathRaw, "png") ||
			strings.HasSuffix(requestPathRaw, "svg") ||
			strings.HasSuffix(requestPathRaw, "gif") ||
			strings.HasSuffix(requestPathRaw, "js") {
			continue
		}

		methodExists := false
		pathFoundAny := false

		for _, model := range modelsMap {
			if model == nil {
				continue
			}

			for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
				specPathUnified := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
				if specPathUnified == normalizedPath {
					pathFoundAny = true
					for op := pathItems.Value().GetOperations().First(); op != nil; op = op.Next() {
						if op.Value() == nil {
							continue
						}
						if strings.ToLower(op.Key()) == methodLower {
							methodExists = true
							break
						}
					}
					break
				}
			}
			if methodExists {
				break
			}
		}

		// If path exists somewhere but method does NOT exist -> shadow
		if pathFoundAny && !methodExists {
			if !contains(shadowApis, normalizedPath, event.RequestMethod, event.ServiceName, event.ClusterName) {
				shadowApis = append(shadowApis, API{
					ClusterName:   event.ClusterName,
					ServiceName:   event.ServiceName,
					RequestMethod: event.RequestMethod,
					RequestPath:   normalizedPath,
					Occurrences:   event.Occurrences,
					Severity:      util.SeverityCritical,
					Request:       event.Request,
					Response:      event.Response,
					StatusCode:    event.ResponseCode,
					Port:          event.Port,
					Type:          util.FindingTypeShadow,
				})
			}
		} else if !pathFoundAny {
			// If path not found in any spec, treat as shadow as well (path missing)
			if !contains(shadowApis, normalizedPath, event.RequestMethod, event.ServiceName, event.ClusterName) {
				shadowApis = append(shadowApis, API{
					ClusterName:   event.ClusterName,
					ServiceName:   event.ServiceName,
					RequestMethod: event.RequestMethod,
					RequestPath:   normalizedPath,
					Occurrences:   event.Occurrences,
					Severity:      util.SeverityCritical,
					Request:       event.Request,
					Response:      event.Response,
					StatusCode:    event.ResponseCode,
					Port:          event.Port,
					Type:          util.FindingTypeShadow,
					LastSeenTime:  event.LastSeenTime,
				})
			}
		}

		// Zombie detection across specs: mark as zombie if any matching operation in any spec is deprecated
		for _, model := range modelsMap {
			if model == nil {
				continue
			}
			for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
				specPathUnified := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
				if specPathUnified == normalizedPath {
					for op := pathItems.Value().GetOperations().First(); op != nil; op = op.Next() {
						if op.Value() != nil && op.Value().Deprecated != nil && *op.Value().Deprecated {
							if !contains(zombieApis, normalizedPath, event.RequestMethod, event.ServiceName, event.ClusterName) {
								zombieApis = append(zombieApis, API{
									ClusterName:   event.ClusterName,
									ServiceName:   event.ServiceName,
									RequestMethod: event.RequestMethod,
									RequestPath:   normalizedPath,
									Occurrences:   event.Occurrences,
									Severity:      util.SeverityHigh,
									Request:       event.Request,
									Response:      event.Response,
									StatusCode:    event.ResponseCode,
									Port:          event.Port,
									Type:          util.FindingTypeZombie,
									LastSeenTime:  event.LastSeenTime,
								})
							}
						}
					}
					break
				}
			}
		}
	}

	return shadowApis, zombieApis
}

// findOrphanApis finds spec-defined endpoints that never received traffic.
func (m *Manager) findOrphanApis(events *hashset.Set, modelsMap map[string]*libopenapi.DocumentModel[v3.Document]) []API {
	var orphanApis []API

	if events == nil || len(modelsMap) == 0 {
		return orphanApis
	}

	trafficked := make(map[string]struct{}, events.Size())
	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}
		requestPath, _ := apispec.GetPathAndQuery(event.RequestPath)
		requestPath = apispec.UnifyParameterizedPathIfApplicable(requestPath, false)
		requestMethod := strings.ToUpper(event.RequestMethod)
		key := fmt.Sprintf("%s/%s", requestMethod, requestPath)
		trafficked[key] = struct{}{}
	}

	// Walk all spec models and produce orphan entries for spec endpoints not present in trafficked set
	seen := make(map[string]struct{}) // dedupe orphans
	for _, model := range modelsMap {
		if model == nil {
			continue
		}
		for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
			specPath := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
			for operations := pathItems.Value().GetOperations().First(); operations != nil; operations = operations.Next() {
				method := strings.ToUpper(operations.Key())
				key := fmt.Sprintf("%s/%s", method, specPath)
				if _, exists := trafficked[key]; exists {
					continue // trafficked -> not orphan
				}
				// dedupe across specs
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				orphanApis = append(orphanApis, API{
					RequestMethod: method,
					RequestPath:   specPath,
					Severity:      util.SeverityLow,
					Type:          util.FindingTypeOrphan,
				})
			}
		}
	}

	return orphanApis
}

func (m *Manager) findActiveApis(events *hashset.Set, modelsMap map[string]*libopenapi.DocumentModel[v3.Document]) []API {

	var activeApis []API

	if events == nil || len(modelsMap) == 0 {
		return activeApis
	}

	trafficked := make(map[string]*API, events.Size())

	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}

		requestPath, _ := apispec.GetPathAndQuery(event.RequestPath)
		normalizedPath := apispec.UnifyParameterizedPathIfApplicable(requestPath, false)
		method := strings.ToUpper(event.RequestMethod)

		key := fmt.Sprintf("%s|%s|%s|%s", event.ClusterName, event.ServiceName, method, normalizedPath)

		if entry, exists := trafficked[key]; exists {
			entry.Occurrences += event.Occurrences
			entry.Request = event.Request
			entry.Response = event.Response
			entry.StatusCode = event.ResponseCode
			entry.Port = event.Port
		} else {
			trafficked[key] = &API{
				ClusterName:   event.ClusterName,
				ServiceName:   event.ServiceName,
				RequestMethod: method,
				RequestPath:   normalizedPath,
				Occurrences:   event.Occurrences,
				Request:       event.Request,
				Response:      event.Response,
				StatusCode:    event.ResponseCode,
				Port:          event.Port,
			}
		}
	}

	seen := make(map[string]struct{})

	for _, model := range modelsMap {
		if model == nil {
			continue
		}

		for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {

			specPath := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)

			for operations := pathItems.Value().GetOperations().First(); operations != nil; operations = operations.Next() {

				method := strings.ToUpper(operations.Key())

				lookupSuffix := fmt.Sprintf("|%s|%s", method, apispec.UnifyParameterizedPathIfApplicable(specPath, false))

				for trafficKey, entry := range trafficked {

					if !strings.HasSuffix(trafficKey, lookupSuffix) {
						continue
					}

					op := operations.Value()

					// Skip deprecated operations
					if op != nil && op.Deprecated != nil && *op.Deprecated {
						continue
					}

					uniqueKey := fmt.Sprintf("%s|%s|%s|%s", entry.ClusterName, entry.ServiceName, entry.RequestMethod, specPath)
					if _, ok := seen[uniqueKey]; ok {
						continue
					}
					seen[uniqueKey] = struct{}{}

					activeApis = append(activeApis, API{
						ClusterName:   entry.ClusterName,
						ServiceName:   entry.ServiceName,
						RequestMethod: entry.RequestMethod,
						RequestPath:   specPath,
						Occurrences:   entry.Occurrences,
						Severity:      util.SeverityInfo,
						Request:       entry.Request,
						Response:      entry.Response,
						StatusCode:    entry.StatusCode,
						Port:          entry.Port,
						Type:          util.FindingTypeActive,
					})
				}
			}
		}
	}

	return activeApis
}

func contains(apis []API, path, method, service, clusterName string) bool {
	for _, api := range apis {
		if api.RequestPath == path && api.RequestMethod == method && api.ServiceName == service && api.ClusterName == clusterName {
			return true
		}
	}
	return false
}
