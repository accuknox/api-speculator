// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package apievent

type ApiEvent struct {
	ClusterName   string      `json:"cluster_name,omitempty"`
	ServiceName   string      `json:"service_name,omitempty"`
	RequestMethod string      `json:"request_method,omitempty"`
	RequestPath   string      `json:"request_path,omitempty"`
	ResponseCode  int         `json:"response_code,omitempty"`
	Occurrences   int         `json:"occurrences,omitempty"`
	Port          int         `json:"port,omitempty"`
	Request       interface{} `json:"request,omitempty"`
	Response      interface{} `json:"response,omitempty"`
}
