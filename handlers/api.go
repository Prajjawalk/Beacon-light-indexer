package handlers

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/services"
	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New().WithField("module", "handlers")

// @Summary Get epoch by number, latest, finalized
// @Tags Epoch
// @Description Returns information for a specified epoch by the epoch number or an epoch tag (can be latest or finalized)
// @Produce  json
// @Param  epoch path string true "Epoch number, the string latest or the string finalized"
// @Success 200 {object} types.ApiResponse{data=types.APIEpochResponse} "Success"
// @Failure 400 {object} types.ApiResponse "Failure"
// @Failure 500 {object} types.ApiResponse "Server Error"
// @Router /api/v1/epoch/{epoch} [get]
func ApiEpoch(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	epoch, err := strconv.ParseInt(c.Param("epoch"), 10, 64)
	if err != nil && c.Param("epoch") != "latest" && c.Param("epoch") != "finalized" {
		sendErrorResponse(c.Writer, c.Request.URL.String(), "invalid epoch provided")
		return
	}

	if c.Param("epoch") == "latest" {
		epoch = int64(services.LatestEpoch())
		logger.Infof("epoch is: %v", epoch)
	}

	if c.Param("epoch") == "finalized" {
		epoch = int64(services.LatestFinalizedEpoch())
	}

	if epoch > int64(services.LatestEpoch()) {
		sendErrorResponse(w, r.URL.String(), fmt.Sprintf("epoch is in the future. The latest epoch is %v", services.LatestEpoch()))
		return
	}

	if epoch < 0 {
		sendErrorResponse(w, r.URL.String(), "epoch must be a positive number")
		return
	}

	rows, err := db.IndexerDb.Query(`SELECT attestationscount, attesterslashingscount, averagevalidatorbalance, blockscount, depositscount, eligibleether, epoch, finalized, globalparticipationrate, proposerslashingscount, rewards_exported, totalvalidatorbalance, validatorscount, voluntaryexitscount, votedether, withdrawalcount, 
		(SELECT COUNT(*) FROM blocks WHERE epoch = $1 AND status = '0') as scheduledblocks,
		(SELECT COUNT(*) FROM blocks WHERE epoch = $1 AND status = '1') as proposedblocks,
		(SELECT COUNT(*) FROM blocks WHERE epoch = $1 AND status = '2') as missedblocks,
		(SELECT COUNT(*) FROM blocks WHERE epoch = $1 AND status = '3') as orphanedblocks
		FROM epochs WHERE epoch = $1`, epoch)
	if err != nil {
		logger.WithError(err).Error("error retrieving epoch data")
		sendServerErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	addEpochTime := func(dataEntryMap map[string]interface{}) error {
		dataEntryMap["ts"] = utils.EpochToTime(uint64(epoch))
		return nil
	}

	returnQueryResults(rows, w, r, addEpochTime)
}

// @Summary Get epoch blocks by epoch number, latest or finalized
// @Tags Epoch
// @Description Returns all slots for a specified epoch
// @Produce  json
// @Param  epoch path string true "Epoch number, the string latest or string finalized"
// @Success 200 {object} types.ApiResponse{data=[]types.APISlotResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/epoch/{epoch}/slots [get]
func ApiEpochSlots(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	epoch, err := strconv.ParseInt(c.Param("epoch"), 10, 64)
	if err != nil && c.Param("epoch") != "latest" && c.Param("epoch") != "finalized" {
		sendErrorResponse(w, r.URL.String(), "invalid epoch provided")
		return
	}

	if c.Param("epoch") == "latest" {
		epoch = int64(services.LatestEpoch())
	}

	if c.Param("epoch") == "finalized" {
		epoch = int64(services.LatestFinalizedEpoch())
	}

	if epoch > int64(services.LatestEpoch()) {
		sendErrorResponse(w, r.URL.String(), fmt.Sprintf("epoch is in the future. The latest epoch is %v", services.LatestEpoch()))
		return
	}

	if epoch < 0 {
		sendErrorResponse(w, r.URL.String(), "epoch must be a positive number")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT attestationscount, attesterslashingscount, blockroot, depositscount, epoch, eth1data_blockhash, eth1data_depositcount, eth1data_depositroot, exec_base_fee_per_gas, exec_block_hash, exec_block_number, exec_extra_data, exec_fee_recipient, exec_gas_limit, exec_gas_used, exec_logs_bloom, exec_parent_hash, exec_random, exec_receipts_root, exec_state_root, exec_timestamp, exec_transactions_count, graffiti, graffiti_text, parentroot, proposer, proposerslashingscount, randaoreveal, signature, slot, stateroot, status, syncaggregate_bits, syncaggregate_participation, syncaggregate_signature, voluntaryexitscount, withdrawalcount FROM blocks WHERE epoch = $1 ORDER BY slot", epoch)
	if err != nil {
		sendServerErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResultsAsArray(rows, w, r)
}

// @Summary Get a slot by its slot number or root hash
// @Tags Slot
// @Description Returns a slot by its slot number or root hash or the latest slot with string latest
// @Produce  json
// @Param  slot path string true "Slot or root hash or the string latest"
// @Success 200 {object} types.ApiResponse{data=types.APISlotResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slotOrHash} [get]
func ApiSlots(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	slotOrHash := strings.Replace(c.Param("slot"), "0x", "", -1)
	blockSlot := int64(-1)
	blockRootHash, err := hex.DecodeString(slotOrHash)
	if slotOrHash != "latest" && (err != nil || len(slotOrHash) != 64) {
		blockRootHash = []byte{}
		blockSlot, err = strconv.ParseInt(c.Param("slot"), 10, 64)
		if err != nil {
			sendErrorResponse(w, r.URL.String(), "could not parse slot number")
			return
		}
	}

	if slotOrHash == "latest" {
		blockSlot = int64(services.LatestSlot())
	}

	if len(blockRootHash) != 32 {
		// blockRootHash is required for the SQL statement below, if none has passed we retrieve it manually
		err := db.IndexerDb.Get(&blockRootHash, `SELECT blockroot FROM blocks WHERE slot = $1`, blockSlot)

		if err != nil || len(blockRootHash) != 32 {
			sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
			return
		}
	}

	rows, err := db.IndexerDb.Query(`
	SELECT
		blocks.epoch,
		blocks.slot,
		blocks.blockroot,
		blocks.parentroot,
		blocks.stateroot,
		blocks.signature,
		blocks.randaoreveal,
		blocks.graffiti,
		blocks.graffiti_text,
		blocks.eth1data_depositroot,
		blocks.eth1data_depositcount,
		blocks.eth1data_blockhash,
		blocks.proposerslashingscount,
		blocks.attesterslashingscount,
		blocks.attestationscount,
		blocks.depositscount,
		blocks.withdrawalcount, 
		blocks.voluntaryexitscount,
		blocks.proposer,
		blocks.status,
		blocks.syncaggregate_bits,
		blocks.syncaggregate_signature,
		blocks.syncaggregate_participation,
		blocks.exec_parent_hash,
		blocks.exec_fee_recipient,
		blocks.exec_state_root,
		blocks.exec_receipts_root,
		blocks.exec_logs_bloom,
		blocks.exec_random,
		blocks.exec_block_number,
		blocks.exec_gas_limit,
		blocks.exec_gas_used,
		blocks.exec_timestamp,
		blocks.exec_extra_data,
		blocks.exec_base_fee_per_gas,
		blocks.exec_block_hash,     
		blocks.exec_transactions_count,
		ba.votes
	FROM
		blocks
	LEFT JOIN
		(SELECT beaconblockroot, sum(array_length(validators, 1)) AS votes FROM blocks_attestations GROUP BY beaconblockroot) ba ON (blocks.blockroot = ba.beaconblockroot)
	WHERE
		blocks.blockroot = $1;`, blockRootHash)

	if err != nil {
		logger.WithError(err).Error("could not retrieve db results")
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResults(rows, w, r)
}

// ApiSlotAttestations godoc
// @Summary Get the attestations included in a specific slot
// @Tags Slot
// @Description Returns the attestations included in a specific slot
// @Produce  json
// @Param  slot path string true "Slot"
// @Success 200 {object} types.ApiResponse{data=[]types.APIAttestationResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slot}/attestations [get]
func ApiSlotAttestations(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	slot, err := strconv.ParseInt(c.Param("slot"), 10, 64)
	if err != nil && c.Param("slot") != "latest" {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	if c.Param("slot") == "latest" {
		slot = int64(services.LatestSlot())
	}

	if slot > int64(services.LatestSlot()) {
		sendErrorResponse(w, r.URL.String(), fmt.Sprintf("slot is in the future. The latest slot is %v", services.LatestSlot()))
		return
	}

	if slot < 0 {
		sendErrorResponse(w, r.URL.String(), "slot must be a positive number")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT aggregationbits, beaconblockroot, block_index, block_root, block_slot, committeeindex, signature, slot, source_epoch, source_root, target_epoch, target_root, validators FROM blocks_attestations WHERE block_slot = $1 ORDER BY block_index", slot)
	if err != nil {
		logger.WithError(err).Error("could not retrieve db results")
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResultsAsArray(rows, w, r)
}

// @Summary Get the deposits included in a specific block
// @Tags Slot
// @Description Returns the deposits included in a specific block
// @Produce  json
// @Param  slot path string true "Block slot"
// @Param  limit query string false "Limit the number of results"
// @Param offset query string false "Offset the number of results"
// @Success 200 {object} types.ApiResponse{[]APIAttestationResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slot}/deposits [get]
func ApiSlotDeposits(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	q := r.URL.Query()

	limitQuery := q.Get("limit")
	offsetQuery := q.Get("offset")

	offset, err := strconv.ParseInt(offsetQuery, 10, 64)
	if err != nil {
		offset = 0
	}

	limit, err := strconv.ParseInt(limitQuery, 10, 64)
	if err != nil {
		limit = 100 + offset
	}

	if offset < 0 {
		offset = 0
	}

	if limit > (100+offset) || limit <= 0 || limit <= offset {
		limit = 100 + offset
	}

	slot, err := strconv.ParseInt(c.Param("slot"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT amount, block_index, block_root, block_slot, proof, publickey, signature, withdrawalcredentials FROM blocks_deposits WHERE block_slot = $1 ORDER BY block_index DESC limit $2 offset $3", slot, limit, offset)
	if err != nil {
		logger.WithError(err).Error("could not retrieve db results")
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResultsAsArray(rows, w, r)
}

// @Summary Get the proposer slashings included in a specific slot
// @Tags Slot
// @Description Returns the proposer slashings included in a specific slot
// @Produce  json
// @Param  slot path string true "Slot"
// @Success 200 {object} types.ApiResponse{data=[]types.APIProposerSlashingResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slot}/proposerslashings [get]
func ApiSlotProposerSlashings(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	slot, err := strconv.ParseInt(c.Param("slot"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT block_index, block_root, block_slot, header1_bodyroot, header1_parentroot, header1_signature, header1_slot, header1_stateroot, header2_bodyroot, header2_parentroot, header2_signature, header2_slot, header2_stateroot, proposerindex FROM blocks_proposerslashings WHERE block_slot = $1 ORDER BY block_index DESC", slot)
	if err != nil {
		logger.WithError(err).Error("could not retrieve db results")
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResultsAsArray(rows, w, r)
}

// @Summary Get the voluntary exits included in a specific slot
// @Tags Slot
// @Description Returns the voluntary exits included in a specific slot
// @Produce  json
// @Param  slot path string true "Slot"
// @Success 200 {object} types.ApiResponse{data=[]types.APIVoluntaryExitResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slot}/voluntaryexits [get]
func ApiSlotVoluntaryExits(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	slot, err := strconv.ParseInt(c.Param("slot"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT block_slot, block_index, block_root, epoch, validatorindex, signature FROM blocks_voluntaryexits WHERE block_slot = $1 ORDER BY block_index DESC", slot)
	if err != nil {
		logger.WithError(err).Error("could not retrieve db results")
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResultsAsArray(rows, w, r)
}

// @Summary Get the withdrawals included in a specific slot
// @Tags Slot
// @Description Returns the withdrawals included in a specific slot
// @Produce json
// @Param slot path string true "Block slot"
// @Success 200 {object} types.ApiResponse
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slot}/withdrawals [get]
func ApiSlotWithdrawals(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	slot, err := strconv.ParseInt(c.Param("slot"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT block_slot, withdrawalindex, validatorindex, address, amount FROM blocks_withdrawals WHERE block_slot = $1 ORDER BY withdrawalindex", slot)
	if err != nil {
		logger.WithError(err).Error("error getting blocks_withdrawals")
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()
	returnQueryResults(rows, w, r)
}

// @Summary Get the attester slashings included in a specific slot
// @Tags Slot
// @Description Returns the attester slashings included in a specific slot
// @Produce  json
// @Param  slot path string true "Slot"
// @Success 200 {object} types.ApiResponse{data=[]types.APIAttesterSlashingResponse}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/slot/{slot}/attesterslashings [get]
func ApiSlotAttesterSlashings(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	slot, err := strconv.ParseInt(c.Param("slot"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	rows, err := db.IndexerDb.Query("SELECT attestation1_beaconblockroot, attestation1_index, attestation1_indices, attestation1_signature, attestation1_slot, attestation1_source_epoch, attestation1_source_root, attestation1_target_epoch, attestation1_target_root, attestation2_beaconblockroot, attestation2_index, attestation2_indices, attestation2_signature, attestation2_slot, attestation2_source_epoch, attestation2_source_root, attestation2_target_epoch, attestation2_target_root, block_index, block_root, block_slot FROM blocks_attesterslashings WHERE block_slot = $1 ORDER BY block_index DESC", slot)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "could not retrieve db results")
		return
	}
	defer rows.Close()

	returnQueryResultsAsArray(rows, w, r)
}

func ApiGlobalParticipationRate(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	var globalParticipationRate float32
	row := db.IndexerDb.QueryRow("SELECT AVG(globalparticipationrate) from epochs;")
	if row != nil {
		err := row.Scan(&globalParticipationRate)
		if err != nil {
			sendErrorResponse(w, r.URL.String(), "could not fetch globalParticipationRate from database")
		}
	}

	j := json.NewEncoder(w)

	sendOKResponse(j, r.URL.String(), []interface{}{struct{ globalParticipationRate float32 }{
		globalParticipationRate: globalParticipationRate * float32(100),
	}})
}

func ApiValidatorParticipationRate(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	index, err := strconv.ParseInt(c.Param("validator_index"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid block slot provided")
		return
	}

	var totalMissedAttestations uint64
	var epoch uint64
	row := db.IndexerDb.QueryRow("SELECT missedattestations, latest_epoch from validator_missed_attestations where validatorindex = $1;", index)
	if row != nil {
		err := row.Scan(&totalMissedAttestations, &epoch)
		if err != nil {
			sendErrorResponse(w, r.URL.String(), "could not fetch validator participation rate from database")
		}
	}

	validatorParticipationRate := float32(1) - float32(totalMissedAttestations/(epoch*utils.Config.Chain.SlotsPerEpoch))

	j := json.NewEncoder(w)
	sendOKResponse(j, r.URL.String(), []interface{}{struct{ validatorParticipationRate float32 }{
		validatorParticipationRate: validatorParticipationRate * float32(100),
	}})
}

func returnQueryResults(rows *sql.Rows, w http.ResponseWriter, r *http.Request, adjustQueryEntriesFuncs ...func(map[string]interface{}) error) {
	j := json.NewEncoder(w)
	data, err := utils.SqlRowsToJSON(rows)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "could not parse db results")
		return
	}

	err = adjustQueryResults(data, adjustQueryEntriesFuncs...)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "could not adjust query results")
		return
	}

	sendOKResponse(j, r.URL.String(), data)
}

// Saves the result of a query converted to JSON in the response writer as an array.
// An arbitrary amount of functions adjustQueryEntriesFuncs can be added to adjust the JSON response.
func returnQueryResultsAsArray(rows *sql.Rows, w http.ResponseWriter, r *http.Request, adjustQueryEntriesFuncs ...func(map[string]interface{}) error) {
	data, err := utils.SqlRowsToJSON(rows)

	if err != nil {
		sendErrorResponse(w, r.URL.String(), "could not parse db results")
		return
	}

	err = adjustQueryResults(data, adjustQueryEntriesFuncs...)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "could not adjust query results")
		return
	}

	response := &types.ApiResponse{
		Status: "OK",
		Data:   data,
	}

	err = json.NewEncoder(w).Encode(response)

	if err != nil {
		logger.Errorf("error serializing json data for API %v route: %v", r.URL.String(), err)
	}
}

func adjustQueryResults(data []interface{}, adjustQueryEntriesFuncs ...func(map[string]interface{}) error) error {
	for _, dataEntry := range data {
		dataEntryMap, ok := dataEntry.(map[string]interface{})
		if !ok {
			return fmt.Errorf("error type asserting query results as a map")
		} else {
			for _, f := range adjustQueryEntriesFuncs {
				if err := f(dataEntryMap); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// SendErrorResponse exposes sendErrorResponse
func SendErrorResponse(w http.ResponseWriter, route, message string) {
	sendErrorResponse(w, route, message)
}

func sendErrorResponse(w http.ResponseWriter, route, message string) {
	sendErrorWithCodeResponse(w, route, message, 400)
}

func sendServerErrorResponse(w http.ResponseWriter, route, message string) {
	sendErrorWithCodeResponse(w, route, message, 500)
}

func sendErrorWithCodeResponse(w http.ResponseWriter, route, message string, errorcode int) {
	w.WriteHeader(errorcode)
	j := json.NewEncoder(w)
	response := &types.ApiResponse{}
	response.Status = "ERROR: " + message
	err := j.Encode(response)

	if err != nil {
		logger.Errorf("error serializing json error for API %v route: %v", route, err)
	}
}

// SendOKResponse exposes sendOKResponse
func SendOKResponse(j *json.Encoder, route string, data []interface{}) {
	sendOKResponse(j, route, data)
}

func sendOKResponse(j *json.Encoder, route string, data []interface{}) {
	response := &types.ApiResponse{}
	response.Status = "OK"

	if len(data) == 1 {
		response.Data = data[0]
	} else {
		response.Data = data
	}
	err := j.Encode(response)

	if err != nil {
		logger.Errorf("error serializing json data for API %v route: %v", route, err)
	}
}
