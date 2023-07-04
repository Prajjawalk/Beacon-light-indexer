package services

import (
	"fmt"
	"sync"
	"time"

	"github.com/Prajjawalk/beacon-light-indexer/cache"
	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New().WithField("module", "services")

// Init will initialize the services
func Init() {
	ready := &sync.WaitGroup{}
	ready.Add(1)
	go epochUpdater(ready)

	ready.Add(1)
	go slotUpdater(ready)
}

func slotUpdater(wg *sync.WaitGroup) {
	firstRun := true

	for {
		slot := uint64(0)
		err := db.IndexerDb.Get(&slot, "SELECT COALESCE(MAX(slot), 0) FROM blocks where slot < $1", utils.TimeToSlot(uint64(time.Now().Add(time.Second*10).Unix())))

		if err != nil {
			logger.Errorf("error retrieving latest slot from the database: %v", err)

			if err.Error() == "sql: database is closed" {
				logger.Fatalf("error retrieving latest slot from the database: %v", err)
			}
		} else {
			cacheKey := fmt.Sprintf("%d:frontend:slot", utils.Config.Chain.DepositChainID)
			err := cache.IndexerCache.SetUint64(cacheKey, slot, time.Hour*24)
			if err != nil {
				logger.Errorf("error caching slot: %v", err)
			}
			if firstRun {
				logger.Info("initialized slot updater")
				wg.Done()
				firstRun = false
			}
		}
		time.Sleep(time.Second)
	}
}

func epochUpdater(wg *sync.WaitGroup) {
	firstRun := true
	for {
		// latest epoch acording to the node
		epochNode := uint64(0)
		err := db.IndexerDb.Get(&epochNode, "SELECT headepoch FROM network_liveness order by headepoch desc LIMIT 1")
		if err != nil {
			logger.Errorf("error retrieving latest node epoch from the database: %v", err)
		} else {
			cacheKey := fmt.Sprintf("%d:indexer:latestNodeEpoch", utils.Config.Chain.DepositChainID)
			err := cache.IndexerCache.SetUint64(cacheKey, epochNode, time.Hour*24)
			if err != nil {
				logger.Errorf("error caching latestNodeEpoch: %v", err)
			}
		}

		// latest finalized epoch acording to the node
		latestNodeFinalized := uint64(0)
		err = db.IndexerDb.Get(&latestNodeFinalized, "SELECT finalizedepoch FROM network_liveness order by headepoch desc LIMIT 1")
		if err != nil {
			logger.Errorf("error retrieving latest node finalized epoch from the database: %v", err)
		} else {
			cacheKey := fmt.Sprintf("%d:indexer:latestNodeFinalizedEpoch", utils.Config.Chain.DepositChainID)
			err := cache.IndexerCache.SetUint64(cacheKey, latestNodeFinalized, time.Hour*24)
			if err != nil {
				logger.Errorf("error caching latestNodeFinalized: %v", err)
			}
		}

		// latest exported epoch
		epoch := uint64(0)
		err = db.IndexerDb.Get(&epoch, "SELECT COALESCE(MAX(epoch), 0) FROM epochs")
		if err != nil {
			logger.Errorf("error retrieving latest exported epoch from the database: %v", err)
		} else {
			cacheKey := fmt.Sprintf("%d:indexer:latestEpoch", utils.Config.Chain.DepositChainID)
			err := cache.IndexerCache.SetUint64(cacheKey, epoch, time.Hour*24)
			if err != nil {
				logger.Errorf("error caching latestEpoch: %v", err)
			}
		}

		// latest exportered finalized epoch
		latestFinalized := uint64(0)
		err = db.IndexerDb.Get(&latestFinalized, "SELECT COALESCE(MAX(epoch), 0) FROM epochs where finalized is true")
		if err != nil {
			logger.Errorf("error retrieving latest exported finalized epoch from the database: %v", err)
		} else {
			cacheKey := fmt.Sprintf("%d:indexer:latestFinalized", utils.Config.Chain.DepositChainID)
			err := cache.IndexerCache.SetUint64(cacheKey, latestFinalized, time.Hour*24)
			if err != nil {
				logger.Errorf("error caching latestFinalizedEpoch: %v", err)
			}
			if firstRun {
				logger.Info("initialized epoch updater")
				wg.Done()
				firstRun = false
			}
		}
		time.Sleep(time.Second)
	}
}

// LatestSlot will return the latest slot
func LatestSlot() uint64 {
	cacheKey := fmt.Sprintf("%d:indexer:slot", utils.Config.Chain.DepositChainID)

	if wanted, err := cache.IndexerCache.GetUint64WithLocalTimeout(cacheKey, time.Second*5); err == nil {
		return wanted
	} else {
		logger.Errorf("error retrieving latest slot from cache: %v", err)
	}
	return 0
}

// LatestEpoch will return the latest epoch
func LatestEpoch() uint64 {
	cacheKey := fmt.Sprintf("%d:indexer:latestEpoch", utils.Config.Chain.DepositChainID)

	if wanted, err := cache.IndexerCache.GetUint64WithLocalTimeout(cacheKey, time.Second*5); err == nil {
		return wanted
	} else {
		logger.Errorf("error retrieving latestEpoch from cache: %v", err)
	}

	return 0
}

func LatestNodeEpoch() uint64 {
	cacheKey := fmt.Sprintf("%d:indexer:latestNodeEpoch", utils.Config.Chain.DepositChainID)

	if wanted, err := cache.IndexerCache.GetUint64WithLocalTimeout(cacheKey, time.Second*5); err == nil {
		return wanted
	} else {
		logger.Errorf("error retrieving latestNodeEpoch from cache: %v", err)
	}

	return 0
}

func LatestNodeFinalizedEpoch() uint64 {
	cacheKey := fmt.Sprintf("%d:indexer:latestNodeFinalizedEpoch", utils.Config.Chain.DepositChainID)

	if wanted, err := cache.IndexerCache.GetUint64WithLocalTimeout(cacheKey, time.Second*5); err == nil {
		return wanted
	} else {
		logger.Errorf("error retrieving latestNodeFinalizedEpoch from cache: %v", err)
	}

	return 0
}

// LatestFinalizedEpoch will return the most recent epoch that has been finalized.
func LatestFinalizedEpoch() uint64 {
	cacheKey := fmt.Sprintf("%d:indexer:latestFinalized", utils.Config.Chain.DepositChainID)

	if wanted, err := cache.IndexerCache.GetUint64WithLocalTimeout(cacheKey, time.Second*5); err == nil {
		return wanted
	} else {
		logger.Errorf("error retrieving latestFinalized for key: %v from cache: %v", cacheKey, err)
	}
	return 0
}
