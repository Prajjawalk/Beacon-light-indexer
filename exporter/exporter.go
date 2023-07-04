package exporter

import (
	"fmt"
	"time"

	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/rpc"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New().WithField("module", "exporter")

// Start will start the export of data from rpc into the database
func Start(client *rpc.BeaconClient) error {
	for {
		head, err := client.GetChainHead()
		if err == nil {
			logger.Infof("Beacon node is available with head slot: %v", head.HeadSlot)
			break
		}
		logger.Errorf("beacon-node seems to be unavailable: %v", err)
		time.Sleep(time.Second * 10)
	}

	logger.Printf("performing index of latest 5 epochs")
	head, err := client.GetChainHead()
	if err != nil {
		logrus.Fatalf("getting chain head from client for full db reindex error: %v", err)
	}

	for epoch := head.HeadEpoch - 5; epoch <= head.HeadEpoch; epoch++ {
		err := ExportEpoch(epoch, client)

		if err != nil {
			logrus.Fatalf("exporting all epochs up to head epoch error: %v", err)
		}
	}

	return nil
}

// ExportEpoch will export an epoch from rpc into the database
func ExportEpoch(epoch uint64, client *rpc.BeaconClient) error {
	start := time.Now()
	defer func() {
		logger.WithFields(logrus.Fields{"duration": time.Since(start), "epoch": epoch}).Info("completed exporting epoch")
	}()

	startGetEpochData := time.Now()
	logger.Printf("retrieving data for epoch %v", epoch)

	data, err := client.GetEpochData(epoch, false)
	if err != nil {
		return fmt.Errorf("error retrieving epoch data: %v", err)
	}

	logger.WithFields(logrus.Fields{"duration": time.Since(startGetEpochData), "epoch": epoch}).Info("completed getting epoch-data")
	logger.Printf("data for epoch %v retrieved, took %v", epoch, time.Since(start))

	err = db.SaveEpoch(data, client)
	if err != nil {
		return fmt.Errorf("error saving epoch data: %w", err)
	}

	return nil
}
