// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/pb33f/libopenapi"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/5gsec/api-speculator/internal/apispec"
	"github.com/5gsec/api-speculator/internal/pathtrie"
)

func (m *Manager) buildModel(oasCfg string) (*libopenapi.DocumentModel[v3.Document], error) {
	var specBytes []byte
	var err error

	if strings.HasPrefix(oasCfg, "http://") || strings.HasPrefix(oasCfg, "https://") {
		specBytes, err = downloadSpec(oasCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to download spec from %s: %w", oasCfg, err)
		}
	} else {
		specBytes, err = os.ReadFile(oasCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to read spec file %s: %w", oasCfg, err)
		}
	}

	if len(specBytes) == 0 {
		return nil, fmt.Errorf("spec at '%s' is empty", oasCfg)
	}

	model, err := apispec.BuildOASV3Model(specBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to build OAS v3 model: %w", err)
	}
	return model, nil
}

func downloadSpec(oasCfg string) ([]byte, error) {
	response, err := http.Get(oasCfg)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (m *Manager) buildTrie(model *libopenapi.DocumentModel[v3.Document]) pathtrie.PathTrie {
	trie := pathtrie.New()
	for paths := model.Model.Paths.PathItems.First(); paths != nil; paths = paths.Next() {
		_ = trie.Insert(paths.Key(), paths.Value())
	}
	return trie
}

// loadSpecModels loads each spec file/url into a libopenapi DocumentModel and returns a map filename->model.
// If a spec fails to parse, it logs the error and skips that file.
func (m *Manager) loadSpecModels(apiSpecFiles []string) map[string]*libopenapi.DocumentModel[v3.Document] {
	models := make(map[string]*libopenapi.DocumentModel[v3.Document], len(apiSpecFiles))
	for _, f := range apiSpecFiles {
		if f == "" {
			continue
		}
		model, err := m.buildModel(f)
		if err != nil {
			m.Logger.Warnf("failed to load spec '%s': %v (skipping)", f, err)
			continue
		}
		models[f] = model
	}
	return models
}
