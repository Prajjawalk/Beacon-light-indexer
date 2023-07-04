package db

import (
	"bytes"
	"crypto/sha1"
	"database/sql"
	"embed"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Prajjawalk/beacon-light-indexer/rpc"
	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/patrickmn/go-cache"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/*.sql
var EmbedMigrations embed.FS

// DB is a pointer to the explorer-database
var IndexerDb *sqlx.DB

var logger = logrus.StandardLogger().WithField("module", "db")

var epochsCache = cache.New(time.Hour, time.Minute)
var saveValidatorsMux = &sync.Mutex{}

func dbTestConnection(dbConn *sqlx.DB, dataBaseName string) {
	// The golang sql driver does not properly implement PingContext
	// therefore we use a timer to catch db connection timeouts
	dbConnectionTimeout := time.NewTimer(15 * time.Second)

	go func() {
		<-dbConnectionTimeout.C
		logrus.Fatalf("timeout while connecting to %s", dataBaseName)
	}()

	err := dbConn.Ping()
	if err != nil {
		logrus.Fatalf("unable to Ping %s: %s", dataBaseName, err)
	}

	dbConnectionTimeout.Stop()
}

func mustInitDB(indexer *types.DatabaseConfig) *sqlx.DB {
	dbConnIndexer, err := sqlx.Open("pgx", fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", indexer.Username, indexer.Password, indexer.Host, indexer.Port, indexer.Name))
	if err != nil {
		logrus.Fatalf("error getting Connection Writer database: %v", err)
	}

	dbTestConnection(dbConnIndexer, "database")
	dbConnIndexer.SetConnMaxIdleTime(time.Second * 30)
	dbConnIndexer.SetConnMaxLifetime(time.Second * 60)
	dbConnIndexer.SetMaxOpenConns(200)
	dbConnIndexer.SetMaxIdleConns(200)

	return dbConnIndexer
}

func MustInitDB(indexer *types.DatabaseConfig) {
	IndexerDb = mustInitDB(indexer)
}

func ApplyEmbeddedDbSchema() error {
	goose.SetBaseFS(EmbedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	if err := goose.Up(IndexerDb.DB, "migrations"); err != nil {
		return err
	}

	return nil
}

func SaveBlock(block *types.Block) error {

	blocksMap := make(map[uint64]map[string]*types.Block)
	if blocksMap[block.Slot] == nil {
		blocksMap[block.Slot] = make(map[string]*types.Block)
	}
	blocksMap[block.Slot][fmt.Sprintf("%x", block.BlockRoot)] = block

	tx, err := IndexerDb.Beginx()
	if err != nil {
		return fmt.Errorf("error starting db transactions: %v", err)
	}
	defer tx.Rollback()

	logger.Infof("exporting block data")
	err = saveBlocks(blocksMap, tx)
	if err != nil {
		logger.Fatalf("error saving blocks to db: %v", err)
		return fmt.Errorf("error saving blocks to db: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("error committing db transaction: %w", err)
	}

	return nil
}

// SaveEpoch will stave the epoch data into the database
func SaveEpoch(data *types.EpochData, client *rpc.BeaconClient) error {
	// Check if we need to export the epoch
	hasher := sha1.New()
	var epochCacheKey string
	if utils.Config.IndexBlocks {
		slots := make([]uint64, 0, len(data.Blocks))
		for slot := range data.Blocks {
			slots = append(slots, slot)
		}
		sort.Slice(slots, func(i, j int) bool {
			return slots[i] < slots[j]
		})

		for _, slot := range slots {
			for _, b := range data.Blocks[slot] {
				hasher.Write(b.BlockRoot)
			}
		}

		epochCacheKey = fmt.Sprintf("%x", hasher.Sum(nil))
		logger.Infof("cache key for epoch %v is %v", data.Epoch, epochCacheKey)

		cachedEpochKey, found := epochsCache.Get(fmt.Sprintf("%v", data.Epoch))
		if found && epochCacheKey == cachedEpochKey.(string) {
			logger.Infof("skipping export of epoch %v as it did not change compared to the previous export run", data.Epoch)
			return nil
		}
	} else {
		hasher.Write([]byte(strconv.FormatUint(data.Epoch, 10)))

		epochCacheKey = fmt.Sprintf("%x", hasher.Sum(nil))
	}
	start := time.Now()
	defer func() {
		logger.WithFields(logrus.Fields{"epoch": data.Epoch, "duration": time.Since(start)}).Info("completed saving epoch")
	}()

	tx, err := IndexerDb.Beginx()
	if err != nil {
		return fmt.Errorf("error starting db transactions: %w", err)
	}
	defer tx.Rollback()

	logger.WithFields(logrus.Fields{"chainEpoch": utils.TimeToEpoch(time.Now()), "exportEpoch": data.Epoch}).Infof("starting export of epoch %v", data.Epoch)
	if utils.Config.IndexBlocks {
		logger.Infof("exporting block data")
		err = saveBlocks(data.Blocks, tx)
		if err != nil {
			logger.Fatalf("error saving blocks to db: %v", err)
			return fmt.Errorf("error saving blocks to db: %w", err)
		}
	}
	logger.Infof("exporting epoch statistics data")
	proposerSlashingsCount := 0
	attesterSlashingsCount := 0
	attestationsCount := 0
	depositCount := 0
	voluntaryExitCount := 0
	withdrawalCount := 0

	if utils.Config.IndexBlocks {
		for _, slot := range data.Blocks {
			for _, b := range slot {
				proposerSlashingsCount += len(b.ProposerSlashings)
				attesterSlashingsCount += len(b.AttesterSlashings)
				attestationsCount += len(b.Attestations)
				depositCount += len(b.Deposits)
				voluntaryExitCount += len(b.VoluntaryExits)
				if b.ExecutionPayload != nil {
					withdrawalCount += len(b.ExecutionPayload.Withdrawals)
				}
			}
		}
	}
	validatorBalanceSum := new(big.Int)
	validatorsCount := 0
	for _, v := range data.Validators {
		if v.ExitEpoch > data.Epoch && v.ActivationEpoch <= data.Epoch {
			validatorsCount++
			validatorBalanceSum = new(big.Int).Add(validatorBalanceSum, new(big.Int).SetUint64(v.Balance))
		}
	}

	validatorBalanceAverage := new(big.Int).Div(validatorBalanceSum, new(big.Int).SetInt64(int64(validatorsCount)))

	finalized := false
	if data.Epoch == 0 {
		finalized = true
	}

	_, err = tx.Exec(`
		INSERT INTO epochs (
			epoch, 
			blockscount, 
			proposerslashingscount, 
			attesterslashingscount, 
			attestationscount, 
			depositscount,
			withdrawalcount,
			voluntaryexitscount, 
			validatorscount, 
			averagevalidatorbalance, 
			totalvalidatorbalance,
			finalized, 
			eligibleether, 
			globalparticipationrate, 
			votedether
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
		ON CONFLICT (epoch) DO UPDATE SET 
			blockscount             = excluded.blockscount, 
			proposerslashingscount  = excluded.proposerslashingscount,
			attesterslashingscount  = excluded.attesterslashingscount,
			attestationscount       = excluded.attestationscount,
			depositscount           = excluded.depositscount,
			withdrawalcount         = excluded.withdrawalcount,
			voluntaryexitscount     = excluded.voluntaryexitscount,
			validatorscount         = excluded.validatorscount,
			averagevalidatorbalance = excluded.averagevalidatorbalance,
			totalvalidatorbalance   = excluded.totalvalidatorbalance,
			eligibleether           = excluded.eligibleether,
			globalparticipationrate = excluded.globalparticipationrate,
			votedether              = excluded.votedether`,
		data.Epoch,
		len(data.Blocks),
		proposerSlashingsCount,
		attesterSlashingsCount,
		attestationsCount,
		depositCount,
		withdrawalCount,
		voluntaryExitCount,
		validatorsCount,
		validatorBalanceAverage.Uint64(),
		validatorBalanceSum.Uint64(),
		finalized,
		data.EpochParticipationStats.EligibleEther,
		data.EpochParticipationStats.GlobalParticipationRate,
		data.EpochParticipationStats.VotedEther)

	if err != nil {
		return fmt.Errorf("error executing save epoch statement: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("error committing db transaction: %w", err)
	}

	lookback := uint64(0)
	if data.Epoch > 3 {
		lookback = data.Epoch - 3
	}
	if utils.Config.IndexBlocks {
		// delete duplicate scheduled slots
		_, err = IndexerDb.Exec("delete from blocks where slot in (select slot from blocks where epoch >= $1 group by slot having count(*) > 1) and blockroot = $2;", lookback, []byte{0x0})
		if err != nil {
			return fmt.Errorf("error cleaning up blocks table: %w", err)
		}

		// delete duplicate missed blocks
		_, err = IndexerDb.Exec("delete from blocks where slot in (select slot from blocks where epoch >= $1 group by slot having count(*) > 1) and blockroot = $2;", lookback, []byte{0x1})
		if err != nil {
			return fmt.Errorf("error cleaning up blocks table: %w", err)
		}
	}

	epochsCache.Set(fmt.Sprintf("%v", data.Epoch), epochCacheKey, cache.DefaultExpiration)
	return nil
}

func saveBlocks(blocks map[uint64]map[string]*types.Block, tx *sqlx.Tx) error {
	stmtBlock, err := tx.Prepare(`
		INSERT INTO blocks (epoch, slot, blockroot, parentroot, stateroot, signature, randaoreveal, graffiti, graffiti_text, eth1data_depositroot, eth1data_depositcount, eth1data_blockhash, syncaggregate_bits, syncaggregate_signature, proposerslashingscount, attesterslashingscount, attestationscount, depositscount, withdrawalcount, voluntaryexitscount, syncaggregate_participation, proposer, status, exec_parent_hash, exec_fee_recipient, exec_state_root, exec_receipts_root, exec_logs_bloom, exec_random, exec_block_number, exec_gas_limit, exec_gas_used, exec_timestamp, exec_extra_data, exec_base_fee_per_gas, exec_block_hash, exec_transactions_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)
		ON CONFLICT (slot, blockroot) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtBlock.Close()

	stmtTransaction, err := tx.Prepare(`
		INSERT INTO blocks_transactions (block_slot, block_index, block_root, raw, txhash, nonce, gas_price, gas_limit, sender, recipient, amount, payload, max_priority_fee_per_gas, max_fee_per_gas)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (block_slot, block_index) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtTransaction.Close()

	stmtWithdrawals, err := tx.Prepare(`
	INSERT INTO blocks_withdrawals (block_slot, block_root, withdrawalindex, validatorindex, address, amount)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (block_slot, block_root, withdrawalindex) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtWithdrawals.Close()

	stmtBLSChange, err := tx.Prepare(`
	INSERT INTO blocks_bls_change (block_slot, block_root, validatorindex, signature, pubkey, address)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (block_slot, block_root, validatorindex) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtBLSChange.Close()

	stmtProposerSlashing, err := tx.Prepare(`
		INSERT INTO blocks_proposerslashings (block_slot, block_index, block_root, proposerindex, header1_slot, header1_parentroot, header1_stateroot, header1_bodyroot, header1_signature, header2_slot, header2_parentroot, header2_stateroot, header2_bodyroot, header2_signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (block_slot, block_index) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtProposerSlashing.Close()

	stmtAttesterSlashing, err := tx.Prepare(`
		INSERT INTO blocks_attesterslashings (block_slot, block_index, block_root, attestation1_indices, attestation1_signature, attestation1_slot, attestation1_index, attestation1_beaconblockroot, attestation1_source_epoch, attestation1_source_root, attestation1_target_epoch, attestation1_target_root, attestation2_indices, attestation2_signature, attestation2_slot, attestation2_index, attestation2_beaconblockroot, attestation2_source_epoch, attestation2_source_root, attestation2_target_epoch, attestation2_target_root)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
		ON CONFLICT (block_slot, block_index) DO UPDATE SET attestation1_indices = excluded.attestation1_indices, attestation2_indices = excluded.attestation2_indices`)
	if err != nil {
		return err
	}
	defer stmtAttesterSlashing.Close()

	stmtAttestations, err := tx.Prepare(`
		INSERT INTO blocks_attestations (block_slot, block_index, block_root, aggregationbits, validators, signature, slot, committeeindex, beaconblockroot, source_epoch, source_root, target_epoch, target_root)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (block_slot, block_index) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtAttestations.Close()

	stmtDeposits, err := tx.Prepare(`
		INSERT INTO blocks_deposits (block_slot, block_index, block_root, proof, publickey, withdrawalcredentials, amount, signature, valid_signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
		ON CONFLICT (block_slot, block_index) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtDeposits.Close()

	stmtVoluntaryExits, err := tx.Prepare(`
		INSERT INTO blocks_voluntaryexits (block_slot, block_index, block_root, epoch, validatorindex, signature)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (block_slot, block_index) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmtVoluntaryExits.Close()

	slots := make([]uint64, 0, len(blocks))
	for slot := range blocks {
		slots = append(slots, slot)
	}
	sort.Slice(slots, func(i, j int) bool {
		return slots[i] < slots[j]
	})

	for _, slot := range slots {
		for _, b := range blocks[slot] {
			start := time.Now()
			blockLog := logger.WithFields(logrus.Fields{"slot": b.Slot, "blockRoot": fmt.Sprintf("%x", b.BlockRoot)})

			var dbBlockRootHash []byte
			err := IndexerDb.Get(&dbBlockRootHash, "SELECT blockroot FROM blocks WHERE slot = $1 and blockroot = $2", b.Slot, b.BlockRoot)
			if err == nil && bytes.Equal(dbBlockRootHash, b.BlockRoot) {
				blockLog.Infof("skipping export of block as it is already present in the db")
				continue
			} else if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("error checking for block in db: %w", err)
			}

			blockLog.WithField("duration", time.Since(start)).Tracef("check if exists")
			t := time.Now()

			res, err := tx.Exec("DELETE FROM blocks WHERE slot = $1 AND length(blockroot) = 1", b.Slot) // Delete placeholder block
			if err != nil {
				return fmt.Errorf("error deleting placeholder block: %w", err)
			}
			ra, err := res.RowsAffected()
			if err != nil && ra > 0 {
				blockLog.Infof("deleted placeholder block")
			}
			blockLog.WithField("duration", time.Since(t)).Tracef("delete placeholder")
			t = time.Now()

			// Set proposer to MAX_SQL_INTEGER if it is the genesis-block (since we are using integers for validator-indices right now)
			if b.Slot == 0 {
				b.Proposer = 2147483647
			}
			syncAggBits := []byte{}
			syncAggSig := []byte{}
			syncAggParticipation := 0.0
			if b.SyncAggregate != nil {
				syncAggBits = b.SyncAggregate.SyncCommitteeBits
				syncAggSig = b.SyncAggregate.SyncCommitteeSignature
				syncAggParticipation = b.SyncAggregate.SyncAggregateParticipation
				// blockLog = blockLog.WithField("syncParticipation", b.SyncAggregate.SyncAggregateParticipation)
			}

			parentHash := []byte{}
			feeRecipient := []byte{}
			stateRoot := []byte{}
			receiptRoot := []byte{}
			logsBloom := []byte{}
			random := []byte{}
			blockNumber := uint64(0)
			gasLimit := uint64(0)
			gasUsed := uint64(0)
			timestamp := uint64(0)
			extraData := []byte{}
			baseFeePerGas := uint64(0)
			blockHash := []byte{}
			txCount := 0
			withdrawalCount := 0
			if b.ExecutionPayload != nil {
				parentHash = b.ExecutionPayload.ParentHash
				feeRecipient = b.ExecutionPayload.FeeRecipient
				stateRoot = b.ExecutionPayload.StateRoot
				receiptRoot = b.ExecutionPayload.ReceiptsRoot
				logsBloom = b.ExecutionPayload.LogsBloom
				random = b.ExecutionPayload.Random
				blockNumber = b.ExecutionPayload.BlockNumber
				gasLimit = b.ExecutionPayload.GasLimit
				gasUsed = b.ExecutionPayload.GasUsed
				timestamp = b.ExecutionPayload.Timestamp
				extraData = b.ExecutionPayload.ExtraData
				baseFeePerGas = b.ExecutionPayload.BaseFeePerGas
				blockHash = b.ExecutionPayload.BlockHash
				txCount = len(b.ExecutionPayload.Transactions)
				withdrawalCount = len(b.ExecutionPayload.Withdrawals)
			}
			_, err = stmtBlock.Exec(
				b.Slot/utils.Config.Chain.SlotsPerEpoch,
				b.Slot,
				b.BlockRoot,
				b.ParentRoot,
				b.StateRoot,
				b.Signature,
				b.RandaoReveal,
				b.Graffiti,
				utils.GraffitiToSring(b.Graffiti),
				b.Eth1Data.DepositRoot,
				b.Eth1Data.DepositCount,
				b.Eth1Data.BlockHash,
				syncAggBits,
				syncAggSig,
				len(b.ProposerSlashings),
				len(b.AttesterSlashings),
				len(b.Attestations),
				len(b.Deposits),
				withdrawalCount,
				len(b.VoluntaryExits),
				syncAggParticipation,
				b.Proposer,
				strconv.FormatUint(b.Status, 10),
				parentHash,
				feeRecipient,
				stateRoot,
				receiptRoot,
				logsBloom,
				random,
				blockNumber,
				gasLimit,
				gasUsed,
				timestamp,
				extraData,
				baseFeePerGas,
				blockHash,
				txCount,
			)
			if err != nil {
				return fmt.Errorf("error executing stmtBlocks for block %v: %w", b.Slot, err)
			}
			blockLog.WithField("duration", time.Since(t)).Tracef("stmtBlock")

			n := time.Now()
			logger.Tracef("done, took %v", time.Since(n))
			logger.Tracef("writing transactions and withdrawal data")
			if payload := b.ExecutionPayload; payload != nil {
				for i, tx := range payload.Transactions {
					_, err := stmtTransaction.Exec(b.Slot, i, b.BlockRoot,
						tx.Raw, tx.TxHash, tx.AccountNonce, tx.Price, tx.GasLimit, tx.Sender, tx.Recipient, tx.Amount, tx.Payload, tx.MaxPriorityFeePerGas, tx.MaxFeePerGas)
					if err != nil {
						return fmt.Errorf("error executing stmtTransaction for block %v: %v", b.Slot, err)
					}
				}
				for _, w := range payload.Withdrawals {
					_, err := stmtWithdrawals.Exec(b.Slot, b.BlockRoot, w.Index, w.ValidatorIndex, w.Address, w.Amount)
					if err != nil {
						return fmt.Errorf("error executing stmtTransaction for block %v: %v", b.Slot, err)
					}
				}
			}
			logger.Tracef("done, took %v", time.Since(n))
			n = time.Now()
			logger.Tracef("writing proposer slashings data")
			for i, ps := range b.ProposerSlashings {
				_, err := stmtProposerSlashing.Exec(b.Slot, i, b.BlockRoot, ps.ProposerIndex, ps.Header1.Slot, ps.Header1.ParentRoot, ps.Header1.StateRoot, ps.Header1.BodyRoot, ps.Header1.Signature, ps.Header2.Slot, ps.Header2.ParentRoot, ps.Header2.StateRoot, ps.Header2.BodyRoot, ps.Header2.Signature)
				if err != nil {
					return fmt.Errorf("error executing stmtProposerSlashing for block %v: %w", b.Slot, err)
				}
			}
			blockLog.WithField("duration", time.Since(n)).Tracef("stmtProposerSlashing")

			n = time.Now()
			logger.Tracef("writing bls change data")
			for _, bls := range b.SignedBLSToExecutionChange {
				_, err := stmtBLSChange.Exec(b.Slot, b.BlockRoot, bls.Message.Validatorindex, bls.Signature, bls.Message.BlsPubkey, bls.Message.Address)
				if err != nil {
					return fmt.Errorf("error executing stmtBLSChange for block %v: %w", b.Slot, err)
				}
			}
			blockLog.WithField("duration", time.Since(n)).Tracef("stmtBLSChange")
			t = time.Now()

			for i, as := range b.AttesterSlashings {
				_, err := stmtAttesterSlashing.Exec(b.Slot, i, b.BlockRoot, pq.Array(as.Attestation1.AttestingIndices), as.Attestation1.Signature, as.Attestation1.Data.Slot, as.Attestation1.Data.CommitteeIndex, as.Attestation1.Data.BeaconBlockRoot, as.Attestation1.Data.Source.Epoch, as.Attestation1.Data.Source.Root, as.Attestation1.Data.Target.Epoch, as.Attestation1.Data.Target.Root, pq.Array(as.Attestation2.AttestingIndices), as.Attestation2.Signature, as.Attestation2.Data.Slot, as.Attestation2.Data.CommitteeIndex, as.Attestation2.Data.BeaconBlockRoot, as.Attestation2.Data.Source.Epoch, as.Attestation2.Data.Source.Root, as.Attestation2.Data.Target.Epoch, as.Attestation2.Data.Target.Root)
				if err != nil {
					return fmt.Errorf("error executing stmtAttesterSlashing for block %v: %w", b.Slot, err)
				}
			}
			blockLog.WithField("duration", time.Since(t)).Tracef("stmtAttesterSlashing")
			t = time.Now()
			for i, a := range b.Attestations {
				_, err = stmtAttestations.Exec(b.Slot, i, b.BlockRoot, a.AggregationBits, pq.Array(a.Attesters), a.Signature, a.Data.Slot, a.Data.CommitteeIndex, a.Data.BeaconBlockRoot, a.Data.Source.Epoch, a.Data.Source.Root, a.Data.Target.Epoch, a.Data.Target.Root)
				if err != nil {
					return fmt.Errorf("error executing stmtAttestations for block %v: %w", b.Slot, err)
				}
			}
			blockLog.WithField("duration", time.Since(t)).Tracef("attestations")
			t = time.Now()

			blockLog.WithField("duration", time.Since(t)).Tracef("deposits")
			t = time.Now()

			for i, ve := range b.VoluntaryExits {
				_, err := stmtVoluntaryExits.Exec(b.Slot, i, b.BlockRoot, ve.Epoch, ve.ValidatorIndex, ve.Signature)
				if err != nil {
					return fmt.Errorf("error executing stmtVoluntaryExits for block %v: %w", b.Slot, err)
				}
			}
			blockLog.WithField("duration", time.Since(t)).Tracef("exits")
			t = time.Now()

			blockLog.WithField("duration", time.Since(t)).Tracef("stmtProposalAssignments")

			blockLog.Infof("! export of block completed, took %v", time.Since(start))
		}
	}

	return nil
}
