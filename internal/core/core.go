// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of API-Speculator

package core

import (
	"context"

	"go.uber.org/zap"

	"github.com/5gsec/api-speculator/internal/config"
	"github.com/5gsec/api-speculator/internal/database"
	"github.com/5gsec/api-speculator/internal/util"
)

type Manager struct {
	Ctx       context.Context
	Logger    *zap.SugaredLogger
	DBHandler *database.Handler
	Cfg       config.Configuration
}

func (m *Manager) close() {
	if m.DBHandler != nil {
		if err := m.DBHandler.Disconnect(); err != nil {
			m.Logger.Errorf("failed to disconnect to database: %v", err)
		}
	}
}

func Run(ctx context.Context, configFilePath string) {
	mgr := &Manager{
		Ctx:    ctx,
		Logger: util.GetLogger(),
	}
	defer mgr.close()

	mgr.Logger.Info("starting speculator")

	cfg, err := config.New(configFilePath, mgr.Logger)
	if err != nil {
		mgr.Logger.Error(err)
		return
	}
	mgr.Cfg = cfg

	dbHandler, err := database.New(mgr.Ctx, mgr.Cfg.Database)
	if err != nil {
		mgr.Logger.Error(err)
		return
	}
	mgr.DBHandler = dbHandler

	eventCollectionName := mgr.Cfg.Database.Collection
	clusterId := mgr.Cfg.Environment.ClusterId
	apiCollectionName := mgr.Cfg.APICollections.DbCollectionName
	collectionNames := mgr.Cfg.APICollections.CollectionNames
	endpoints := mgr.Cfg.Endpoints

	events, err := mgr.findApiOperationDocuments(eventCollectionName, apiCollectionName, clusterId, collectionNames, endpoints)
	if err != nil {
		mgr.Logger.Errorf("failed to find documents: %v", err)
		return
	}
	if events.Size() == 0 {
		return
	}

	model, _ := mgr.buildModel(mgr.Cfg.OpenAPISpec)
	trie := mgr.buildTrie(model)

	shadowApis, zombieApis := mgr.findShadowAndZombieApi(trie, events, model)
	orphanApis := mgr.findOrphanApi(events, model)
	if err := mgr.exportJsonReport(mgr.Cfg.Exporter.JsonReportFilePath, shadowApis, zombieApis, orphanApis); err != nil {
		mgr.Logger.Error(err)
		return
	}
	mgr.Logger.Infof("successfully generated `%s` JSON report", mgr.Cfg.Exporter.JsonReportFilePath)
}
