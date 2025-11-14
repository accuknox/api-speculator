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

// findShadowAndZombieApi finds shadow (traffic not in trie/spec) and zombie (deprecated in spec but seen in traffic) APIs.
func (m *Manager) findShadowAndZombieApi(trie pathtrie.PathTrie, events *hashset.Set, model *libopenapi.DocumentModel[v3.Document]) ([]API, []API) {
	var shadowApis []API
	var zombieApis []API

	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}
		requestPathRaw, _ := apispec.GetPathAndQuery(event.RequestPath)
		normalizedPath := apispec.UnifyParameterizedPathIfApplicable(requestPathRaw, false)
		methodLower := strings.ToLower(event.RequestMethod)

		// Skip static assets and root endpoint
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
		pathFound := false

		if _, _, found := trie.GetPathAndValue(normalizedPath); found {
			pathFound = true
		}

		for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
			specPathUnified := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
			if specPathUnified == normalizedPath {
				pathFound = true
				for op := pathItems.Value().GetOperations().First(); op != nil; op = op.Next() {
					if op.Value() == nil {
						continue
					}
					opMethod := strings.ToLower(op.Key())
					if opMethod == methodLower {
						methodExists = true
						break
					}
				}
				break
			}
		}

		// If path exists but method does NOT exist -> treat as shadow
		if !methodExists {
			if !contains(shadowApis, normalizedPath, event.RequestMethod, event.ServiceName) {
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
		}

		// If path+method exists but operation is marked deprecated -> treat as zombie
		if pathFound {
			if pi, found := model.Model.Paths.PathItems.Get(requestPathRaw); found {
				for op := pi.GetOperations().First(); op != nil; op = op.Next() {
					if op.Value() != nil && op.Value().Deprecated != nil && *op.Value().Deprecated {
						if !contains(zombieApis, normalizedPath, event.RequestMethod, event.ServiceName) {
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
							})
						}
					}
				}
			} else {
				// fallback: search by unified form
				for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
					specPathUnified := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
					if specPathUnified == normalizedPath {
						for op := pathItems.Value().GetOperations().First(); op != nil; op = op.Next() {
							if op.Value() != nil && op.Value().Deprecated != nil && *op.Value().Deprecated {
								if !contains(zombieApis, normalizedPath, event.RequestMethod, event.ServiceName) {
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
									})
								}
							}
						}
						break
					}
				}
			}
		}
	}

	return shadowApis, zombieApis
}

// findOrphanApi finds spec-defined endpoints that never received traffic.
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
				orphanApis = append(orphanApis, API{
					RequestMethod: requestMethod,
					RequestPath:   requestPath,
					Severity:      util.SeverityLow,
					Type:          util.FindingTypeOrphan,
				})
			}
		}
	}

	return orphanApis
}

func (m *Manager) findActiveApis(events *hashset.Set, model *libopenapi.DocumentModel[v3.Document]) []API {
	var activeApis []API

	// Build map of trafficked endpoints keyed by "METHOD/normalizedPath"
	trafficked := make(map[string]*API, events.Size())

	for _, value := range events.Values() {
		event, ok := value.(apievent.ApiEvent)
		if !ok {
			m.Logger.Warnf("failed to parse endpoint `%v`", value)
			continue
		}

		requestPath, _ := apispec.GetPathAndQuery(event.RequestPath)
		// normalize parameterized paths for matching with spec paths
		normalizedPath := apispec.UnifyParameterizedPathIfApplicable(requestPath, false)
		requestMethod := strings.ToUpper(event.RequestMethod)
		key := fmt.Sprintf("%s/%s", requestMethod, normalizedPath)

		// Aggregate occurrences and keep representative metadata
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
				RequestMethod: requestMethod,
				RequestPath:   normalizedPath,
				Occurrences:   event.Occurrences,
				Request:       event.Request,
				Response:      event.Response,
				StatusCode:    event.ResponseCode,
				Port:          event.Port,
			}
		}
	}

	// Walk the spec paths and mark those trafficked + not deprecated as active
	for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
		specPath := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
		for operations := pathItems.Value().GetOperations().First(); operations != nil; operations = operations.Next() {
			method := strings.ToUpper(operations.Key())
			key := fmt.Sprintf("%s/%s", method, specPath)

			// If trafficked and operation not marked deprecated -> active
			if entry, exists := trafficked[key]; exists {
				op := operations.Value()
				if op != nil && op.Deprecated != nil && *op.Deprecated {
					// zombie API; skip.
					continue
				}

				found := false
				for _, a := range activeApis {
					if a.RequestMethod == entry.RequestMethod && a.RequestPath == entry.RequestPath && a.ServiceName == entry.ServiceName {
						found = true
						break
					}
				}
				if !found {
					activeApis = append(activeApis, API{
						ClusterName:   entry.ClusterName,
						ServiceName:   entry.ServiceName,
						RequestMethod: entry.RequestMethod,
						RequestPath:   entry.RequestPath,
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

func contains(apis []API, path, method, service string) bool {
	for _, api := range apis {
		if api.RequestPath == path &&
			api.RequestMethod == method &&
			api.ServiceName == service {
			return true
		}
	}
	return false
}
