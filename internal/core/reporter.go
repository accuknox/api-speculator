// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/5gsec/api-speculator/internal/apispec"
	"github.com/pb33f/libopenapi"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

type API struct {
	ClusterName            string        `json:"clusterName,omitempty"`
	ServiceName            string        `json:"serviceName,omitempty"`
	RequestMethod          string        `json:"requestMethod"`
	RequestPath            string        `json:"requestPath"`
	Occurrences            int           `json:"occurrences,omitempty"`
	Severity               string        `json:"severity,omitempty"`
	StatusCode             int           `json:"status_code,omitempty"`
	Port                   int           `json:"port,omitempty"`
	Request                interface{}   `json:"request,omitempty"`
	Response               interface{}   `json:"response,omitempty"`
	AssociatedApiSpecFiles []ApiSpecFile `json:"associatedApiSpecFiles,omitempty"`
	Type                   string        `json:"type,omitempty"`
}

type apiReport struct {
	TenantId           int           `json:"tenantId"`
	ScanName           string        `json:"scan_name"`
	ScanTimestamp      string        `json:"scanTimestamp,omitempty"`
	ScopedApiSpecFiles []ApiSpecFile `json:"scopedApiSpecFiles,omitempty"`
	Collections        []string      `json:"collections,omitempty"`
	ShadowAPIs         []API         `json:"shadowApis,omitempty"`
	ZombieAPIs         []API         `json:"zombieApis,omitempty"`
	OrphanAPIs         []API         `json:"orphanApis,omitempty"`
	ActiveAPIs         []API         `json:"activeApis,omitempty"`
}

type ApiSpecFile struct {
	FileName string `json:"fileName"`
	Title    string `json:"title"`
}

// exportJsonReport now accepts modelsMap which holds parsed models for each spec file
func (m *Manager) exportJsonReport(reportFilePath string, shadowApis, zombieApis, orphanApis, activeApis []API, collections []string, modelsMap map[string]*libopenapi.DocumentModel[v3.Document]) error {
	// Build top-level scopedApiSpecFiles from modelsMap
	scopedFiles := make([]ApiSpecFile, 0, len(modelsMap))
	for fileName, model := range modelsMap {
		title := getModelTitleSafe(model)
		scopedFiles = append(scopedFiles, ApiSpecFile{
			FileName: fileName,
			Title:    title,
		})
	}

	// Attach associations to each finding
	attachAssociatedSpecFilesToFindings(shadowApis, modelsMap)
	attachAssociatedSpecFilesToFindings(zombieApis, modelsMap)
	attachAssociatedSpecFilesToFindings(orphanApis, modelsMap)
	attachAssociatedSpecFilesToFindings(activeApis, modelsMap)

	nowUTC := time.Now().UTC()

	report := apiReport{
		TenantId:           m.Cfg.Environment.TenantId,
		ScanName:           m.Cfg.ScanName,
		ScanTimestamp:      nowUTC.Format(time.RFC3339),
		ScopedApiSpecFiles: scopedFiles,
		Collections:        collections,
		ShadowAPIs:         shadowApis,
		ZombieAPIs:         zombieApis,
		OrphanAPIs:         orphanApis,
		ActiveAPIs:         activeApis,
	}

	f, err := os.OpenFile(reportFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			m.Logger.Error("failed to close file", err)
		}
	}()

	bytesToWrite, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		return err
	}

	if _, err = f.Write(bytesToWrite); err != nil {
		return err
	}

	return nil
}

// attachAssociatedSpecFilesToFindings inspects each finding and assigns the list
// of spec files (from modelsMap) that actually define that endpoint+method.
func attachAssociatedSpecFilesToFindings(apis []API, modelsMap map[string]*libopenapi.DocumentModel[v3.Document]) {
	if len(apis) == 0 || len(modelsMap) == 0 {
		return
	}

	for i := range apis {
		api := &apis[i]
		reqPath := api.RequestPath
		reqMethod := strings.ToUpper(api.RequestMethod)
		var assoc []ApiSpecFile
		seen := make(map[string]struct{})

		// Check every model for a matching path + method
		for fileName, model := range modelsMap {
			if model == nil {
				continue
			}

			// Direct path lookup first (exact path key)
			if pi, ok := model.Model.Paths.PathItems.Get(reqPath); ok {
				// ensure operation for method exists
				for ops := pi.GetOperations().First(); ops != nil; ops = ops.Next() {
					if strings.ToUpper(ops.Key()) == reqMethod {
						if _, s := seen[fileName]; !s {
							assoc = append(assoc, ApiSpecFile{FileName: fileName, Title: getModelTitleSafe(model)})
							seen[fileName] = struct{}{}
						}
						goto nextModel
					}
				}
			}

			// Try parameterized/unified match by iterating spec paths
			for pathItems := model.Model.Paths.PathItems.First(); pathItems != nil; pathItems = pathItems.Next() {
				specPathUnified := apispec.UnifyParameterizedPathIfApplicable(pathItems.Key(), true)
				if specPathUnified == reqPath {
					// confirm operation/method exists
					for ops := pathItems.Value().GetOperations().First(); ops != nil; ops = ops.Next() {
						if strings.ToUpper(ops.Key()) == reqMethod {
							if _, s := seen[fileName]; !s {
								assoc = append(assoc, ApiSpecFile{FileName: fileName, Title: getModelTitleSafe(model)})
								seen[fileName] = struct{}{}
							}
							goto nextModel
						}
					}
				}
			}
		nextModel:
		}

		if len(assoc) > 0 {
			api.AssociatedApiSpecFiles = assoc
		}
	}
}

func getModelTitleSafe(model *libopenapi.DocumentModel[v3.Document]) string {
	if model != nil && model.Model.Info != nil {
		return model.Model.Info.Title
	}
	return ""
}

// RemoveDuplicateFindings removes duplicate API findings based on RequestMethod + RequestPath + ServiceName.
func RemoveDuplicateFindings(findings []API) []API {
	unique := make(map[string]API, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s|%s|%s", strings.ToUpper(f.RequestMethod), f.RequestPath, f.ServiceName)
		unique[key] = f
	}

	result := make([]API, 0, len(unique))
	for _, v := range unique {
		result = append(result, v)
	}
	return result
}
