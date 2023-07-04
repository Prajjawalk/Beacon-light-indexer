package main

import (
	"flag"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/Prajjawalk/beacon-light-indexer/cache"
	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/exporter"
	"github.com/Prajjawalk/beacon-light-indexer/handlers"
	"github.com/Prajjawalk/beacon-light-indexer/rpc"
	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/sirupsen/logrus"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file, if empty string defaults will be used")

	flag.Parse()

	cfg := &types.Config{}
	err := utils.ReadConfig(cfg, *configPath)
	if err != nil {
		logrus.Fatalf("error reading config file: %v", err)
	}
	utils.Config = cfg
	logrus.WithFields(logrus.Fields{
		"config":    *configPath,
		"chainName": utils.Config.Chain.Name}).Printf("starting")

	if utils.Config.Chain.SlotsPerEpoch == 0 || utils.Config.Chain.SecondsPerSlot == 0 {
		logrus.Fatal("invalid chain configuration specified, you must specify the slots per epoch, seconds per slot and genesis timestamp in the config file")
	}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		db.MustInitDB(&types.DatabaseConfig{
			Username: cfg.IndexerDatabase.Username,
			Password: cfg.IndexerDatabase.Password,
			Name:     cfg.IndexerDatabase.Name,
			Host:     cfg.IndexerDatabase.Host,
			Port:     cfg.IndexerDatabase.Port,
		})
	}()

	wg.Wait()

	defer db.IndexerDb.Close()

	cache.MustInitIndexerCache()

	chainIDBig := new(big.Int).SetUint64(utils.Config.Chain.DepositChainID)
	rpcClient := rpc.NewBeaconClient(cfg.BeaconNodeUrl, chainIDBig)
	if err != nil {
		logrus.Fatalf("new explorer lighthouse client error %v", err)
	}

	go exporter.Start(rpcClient)

	// services.Init()

	router := gin.Default()

	apiV1Router := router.Group("/api/v1")
	router.GET("/api/v1/docs/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	apiV1Router.GET("/epoch/{epoch}", handlers.ApiEpoch)

	apiV1Router.GET("/epoch/{epoch}/blocks", handlers.ApiEpochSlots)
	apiV1Router.GET("/epoch/{epoch}/slots", handlers.ApiEpochSlots)
	apiV1Router.GET("/slot/{slotOrHash}", handlers.ApiSlots)
	apiV1Router.GET("/slot/{slot}/attestations", handlers.ApiSlotAttestations)
	apiV1Router.GET("/slot/{slot}/deposits", handlers.ApiSlotDeposits)
	apiV1Router.GET("/slot/{slot}/attesterslashings", handlers.ApiSlotAttesterSlashings)
	apiV1Router.GET("/slot/{slot}/proposerslashings", handlers.ApiSlotProposerSlashings)
	apiV1Router.GET("/slot/{slot}/voluntaryexits", handlers.ApiSlotVoluntaryExits)
	apiV1Router.GET("/slot/{slot}/withdrawals", handlers.ApiSlotWithdrawals)

	s := &http.Server{
		Addr:           utils.Config.Server.Host + ":" + utils.Config.Server.Port,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.ListenAndServe()
	utils.WaitForCtrlC()
}
