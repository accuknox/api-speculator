// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/5gsec/api-speculator/internal/core"
	"github.com/5gsec/api-speculator/internal/util"
)

var (
	configFilePath string
	debugMode      bool
)

func init() {
	RootCmd.PersistentFlags().StringVar(&configFilePath, "config", "", "config file path")
	RootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "run in debug mode")
}

var RootCmd = &cobra.Command{
	Use:   "speculator",
	Short: "speculator is a utility that identifies shadow, orphan, and zombie APIs by analyzing API traffic against provided API specifications",

	Long: `speculator helps you secure your APIs by identifying shadow, orphan, and zombie APIs.

By analyzing API traffic in conjunction with your API specifications (e.g., OpenAPI, Swagger), speculator can detect:
  * Shadow APIs: Endpoints that are implemented and functional but not documented in your API specification.
  * Zombie APIs: Endpoints that are deprecated or abandoned in your API specification but are still in use.
  * Orphan APIs: Endpoints that are defined in your API specification but are never invoked in the observed traffic.
  * Active APIs: Endpoints that are defined in your API specification and are also invoked in observed traffic.
`,
	//Long: `A Utility to identify Shadow and Zombie APIs provided API Specification`,
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

func run() {
	util.InitLogger(debugMode)
	logBuildInfo(util.GetLogger())
	ctx := setupSignalHandler()
	core.Run(ctx, configFilePath)
}

// setupSignalHandler registers for SIGTERM and SIGINT. A context is returned
// which is canceled on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func setupSignalHandler() context.Context {
	onlyOneSignalHandler := make(chan struct{})
	close(onlyOneSignalHandler) // panics when called twice

	var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return ctx
}
