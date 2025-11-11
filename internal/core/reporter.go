// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package core

import (
	"encoding/json"
	"os"
)

type API struct {
	ClusterName   string      `json:"clusterName,omitempty"`
	ServiceName   string      `json:"serviceName,omitempty"`
	RequestMethod string      `json:"requestMethod"`
	RequestPath   string      `json:"requestPath"`
	Occurrences   int         `json:"occurrences,omitempty"`
	Severity      string      `json:"severity,omitempty"`
	StatusCode    int         `json:"status_code,omitempty"`
	Port          int         `json:"port,omitempty"`
	Request       interface{} `json:"request,omitempty"`
	Response      interface{} `json:"response,omitempty"`
}

type apiReport struct {
	TenantId    int      `json:"tenantId"`
	ScanName    string   `json:"scan_name"`
	Collections []string `json:"collections,omitempty"`
	ShadowAPIs  []API    `json:"shadowApis,omitempty"`
	ZombieAPIs  []API    `json:"zombieApis,omitempty"`
	OrphanAPIs  []API    `json:"orphanApis,omitempty"`
}

func (m *Manager) exportJsonReport(reportFilePath string, shadowApis, zombieApis, orphanApis []API, collections []string) error {
	report := apiReport{
		TenantId:    m.Cfg.Environment.TenantId,
		ScanName:    m.Cfg.ScanName,
		Collections: collections,
		ShadowAPIs:  shadowApis,
		ZombieAPIs:  zombieApis,
		OrphanAPIs:  orphanApis,
	}

	f, err := os.OpenFile(reportFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		if err := f.Close(); err != nil {
			m.Logger.Error("failed to close file", err)
		}
	}(f)

	bytesToWrite, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		return err
	}
	if _, err = f.Write(bytesToWrite); err != nil {
		return err
	}

	return nil
}
