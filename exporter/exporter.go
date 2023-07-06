package exporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/rpc"
	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New().WithField("module", "exporter")

// Start will start the export of data from rpc into the database
func Start(client *rpc.BeaconClient) error {
	go networkLivenessUpdater(*client)

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

	exportValidatorMissedAttestations(client, data.Validators, epoch)

	err = db.SaveEpoch(data, client)
	if err != nil {
		return fmt.Errorf("error saving epoch data: %w", err)
	}

	return nil
}

func networkLivenessUpdater(client rpc.BeaconClient) {
	var prevHeadEpoch uint64
	err := db.IndexerDb.Get(&prevHeadEpoch, "SELECT COALESCE(MAX(headepoch), 0) FROM network_liveness")
	if err != nil {
		logrus.Fatalf("getting previous head epoch from db error: %v", err)
	}

	epochDuration := time.Second * time.Duration(utils.Config.Chain.SecondsPerSlot*utils.Config.Chain.SlotsPerEpoch)
	slotDuration := time.Second * time.Duration(utils.Config.Chain.SecondsPerSlot)

	for {
		head, err := client.GetChainHead()
		if err != nil {
			logger.Errorf("error getting chainhead when exporting networkliveness: %v", err)
			time.Sleep(slotDuration)
			continue
		}

		if prevHeadEpoch == head.HeadEpoch {
			time.Sleep(slotDuration)
			continue
		}

		// wait for node to be synced
		if time.Now().Add(-epochDuration).After(utils.EpochToTime(head.HeadEpoch)) {
			time.Sleep(slotDuration)
			continue
		}

		_, err = db.IndexerDb.Exec(`
			INSERT INTO network_liveness (ts, headepoch, finalizedepoch, justifiedepoch, previousjustifiedepoch)
			VALUES (NOW(), $1, $2, $3, $4)`,
			head.HeadEpoch, head.FinalizedEpoch, head.JustifiedEpoch, head.PreviousJustifiedEpoch)
		if err != nil {
			logger.Errorf("error saving networkliveness: %v", err)
		} else {
			logger.Printf("updated networkliveness for epoch %v", head.HeadEpoch)
			prevHeadEpoch = head.HeadEpoch
		}

		time.Sleep(slotDuration)
	}
}

func exportValidatorMissedAttestations(client *rpc.BeaconClient, validators []*types.Validator, epoch uint64) {
	validatorMissedAttestations, err := client.GetValidatorMissedAttestationsCount(validators, epoch)
	if err != nil {
		logger.Errorf("error while getting missed attestations for validators: %v", err)
	}

	maArr := make([]*types.ValidatorMissedAttestationsStatistic, 0, len(validatorMissedAttestations))
	for _, stat := range validatorMissedAttestations {
		maArr = append(maArr, stat)
	}

	tx, err := db.IndexerDb.Beginx()
	if err != nil {
		logger.Error(err)
		return
	}

	batchSize := 16000 // max parameters: 65535

	for b := 0; b < len(maArr); b += batchSize {
		start := b
		end := b + batchSize
		if len(maArr) < end {
			end = len(maArr)
		}

		numArgs := 3
		valueStrings := make([]string, 0, batchSize)
		valueArgs := make([]interface{}, 0, batchSize*numArgs)
		for i, stat := range maArr[start:end] {
			valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d)", i*numArgs+1, i*numArgs+2, i*numArgs+3))
			valueArgs = append(valueArgs, stat.Index)
			valueArgs = append(valueArgs, stat.Epoch)
			valueArgs = append(valueArgs, stat.MissedAttestations)
		}
		stmt := fmt.Sprintf(`insert into validator_missed_attestations (validatorindex, latest_epoch, missedattestations) VALUES
		%s on conflict(validatorindex) do update set missedattestations = validator_missed_attestations.missedattestations + excluded.missedattestations, latest_epoch = excluded.latest_epoch;`, strings.Join(valueStrings, ","))
		_, err := tx.Exec(stmt, valueArgs...)

		if err != nil {
			logger.Errorf("error while saving missed attestations to db: %v", err)
			return
		}

		logger.Infof("saving missed attestations batch %v completed", b)
	}

	err = tx.Commit()
	if err != nil {
		logger.Errorf("error while committing transaction to database: %v", err)
		return
	}

}
