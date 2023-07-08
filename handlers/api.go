package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Prajjawalk/beacon-light-indexer/db"
	_ "github.com/Prajjawalk/beacon-light-indexer/docs"
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

// @Summary Get the global participation rate
// @Description Returns the global participation rate upto the latest head epoch
// @Produce  json
// @Success 200 {object} types.ApiResponse{data=types.GlobalParticipationRateResp}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/participationrate/global [get]
func ApiGlobalParticipationRate(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	var globalParticipationRate float32
	row := db.IndexerDb.QueryRow("SELECT AVG(globalparticipationrate) AS globalparticipationrate FROM epochs;")
	if row != nil {
		err := row.Scan(&globalParticipationRate)
		if err != nil {
			sendErrorResponse(w, r.URL.String(), "could not fetch globalParticipationRate from database")
		}
	}

	j := json.NewEncoder(w)
	response := &types.ApiResponse{}
	response.Status = "OK"
	response.Data = &types.GlobalParticipationRateResp{
		ParticipationRate: globalParticipationRate * 100,
	}

	j.Encode(response)
}

// @Summary Get the validator participation rate
// @Description Returns the participation rate of the individual validator upto the latest head epoch
// @Param  validator_index path string true "Index"
// @Produce  json
// @Success 200 {object} types.ApiResponse{data=types.ValidatorParticipationrateResp}
// @Failure 400 {object} types.ApiResponse
// @Router /api/v1/participationrate/validator/:validator_index [get]
func ApiValidatorParticipationRate(c *gin.Context) {
	w := c.Writer
	r := c.Request
	w.Header().Set("Content-Type", "application/json")

	index, err := strconv.ParseInt(c.Param("validator_index"), 10, 64)
	if err != nil {
		sendErrorResponse(w, r.URL.String(), "invalid validator index provided")
		return
	}

	var totalMissedAttestations uint64
	var epoch uint64
	row := db.IndexerDb.QueryRow("SELECT missedattestations, latest_epoch FROM validator_missed_attestations WHERE validatorindex = $1;", index)
	if row != nil {
		err := row.Scan(&totalMissedAttestations, &epoch)
		if err != nil {
			logger.Error(err)
			sendErrorResponse(w, r.URL.String(), "could not fetch validator participation rate from database")
		}
	}

	validatorParticipationRate := float32(1) - float32(float32(totalMissedAttestations)/float32(epoch*utils.Config.Chain.SlotsPerEpoch))

	response := &types.ApiResponse{}
	response.Status = "OK"
	response.Data = &types.ValidatorParticipationrateResp{
		ParticipationRate: validatorParticipationRate * 100,
		Index:             uint64(index),
	}
	j := json.NewEncoder(w)
	j.Encode(response)
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
