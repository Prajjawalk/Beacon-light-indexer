package main

import (
	"flag"

	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/sirupsen/logrus"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	cfg := &types.Config{}
	err := utils.ReadConfig(cfg, *configPath)
	if err != nil {
		logrus.Fatalf("error reading config file: %v", err)
	}
	utils.Config = cfg

	db.MustInitDB(&types.DatabaseConfig{
		Username: cfg.IndexerDatabase.Username,
		Password: cfg.IndexerDatabase.Password,
		Name:     cfg.IndexerDatabase.Name,
		Host:     cfg.IndexerDatabase.Host,
		Port:     cfg.IndexerDatabase.Port,
	})

	defer db.IndexerDb.Close()

	logrus.Infof("applying db schema")
	err = db.ApplyEmbeddedDbSchema()
	if err != nil {
		logrus.WithError(err).Fatal("error applying db schema")
	}
	logrus.Infof("db schema applied successfully")
}
