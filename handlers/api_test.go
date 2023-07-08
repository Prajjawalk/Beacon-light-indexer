package handlers

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Prajjawalk/beacon-light-indexer/cache"
	"github.com/Prajjawalk/beacon-light-indexer/db"
	"github.com/Prajjawalk/beacon-light-indexer/services"
	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
)

func TestApiEpoch(t *testing.T) {
	utils.Config = &types.Config{}
	utils.Config.Chain.DepositChainID = 5

	type args struct {
		params          []gin.Param
		expectedErrCode uint64
		expectedErr     string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test latest epoch",
			args: args{
				params:          []gin.Param{{Key: "epoch", Value: "latest"}},
				expectedErr:     "",
				expectedErrCode: 200,
			},
		},
		{
			name: "Test finalized epoch",
			args: args{
				params:          []gin.Param{{Key: "epoch", Value: "finalized"}},
				expectedErr:     "",
				expectedErrCode: 200,
			},
		},
		{
			name: "Test invalid epoch",
			args: args{
				params:          []gin.Param{{Key: "epoch", Value: "invalid"}},
				expectedErr:     "invalid epoch provided",
				expectedErrCode: 400,
			},
		},
	}
	for _, tt := range tests {
		gin.SetMode(gin.TestMode)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		cache.MustInitIndexerCache()
		c.Params = tt.args.params
		c.Request = &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		defer mockDB.Close()
		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db.IndexerDb = sqlxDB
		epoch, ok := c.Params.Get("epoch")
		if !ok && tt.args.expectedErr == "" {
			t.Errorf("unexpected error while trying to get epoch parameter")
		}

		expectedEpochReturned := int64(0)
		if epoch == "latest" {
			expectedEpochReturned = int64(services.LatestEpoch())
		}

		if epoch == "finalized" {
			expectedEpochReturned = int64(services.LatestFinalizedEpoch())
		}
		epochrows := sqlmock.NewRows([]string{"attestationscount", "attesterslashingscount", "averagevalidatorbalance", "blockscount", "depositscount", "eligibleether", "epoch", "finalized", "globalparticipationrate", "proposerslashingscount", "rewards_exported", "totalvalidatorbalance", "validatorscount", "voluntaryexitscount", "votedether", "withdrawalcount", "scheduledblocks", "proposedblocks", "missedblocks", "orphanedblocks"}).AddRow(0, 0, 33358504520, 32, 0, 16324096000000000, expectedEpochReturned, false, 0.9121949672, 0, false, 15910805749924103, 476964, 0, 4096000000000, 0, 0, 0, 32, 0)
		blockrows := sqlmock.NewRows([]string{"count"}).AddRow(10)
		mock.ExpectQuery("^SELECT (.+) FROM epochs WHERE").WithArgs(expectedEpochReturned).WillReturnRows(epochrows)
		mock.ExpectQuery("SELECT COUNT(*) FROM blocks WHERE").WithArgs(expectedEpochReturned).WillReturnRows(blockrows)
		t.Run(tt.name, func(t *testing.T) {
			ApiEpoch(c)
		})

		if w.Code != int(tt.args.expectedErrCode) {
			b, _ := ioutil.ReadAll(w.Body)
			t.Error(w.Code, string(b))
		}
	}
}

func TestApiEpochSlots(t *testing.T) {
	utils.Config = &types.Config{}
	utils.Config.Chain.DepositChainID = 5

	type args struct {
		params      []gin.Param
		expectedErr error
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test latest epoch",
			args: args{
				params:      []gin.Param{{Key: "epoch", Value: "latest"}},
				expectedErr: nil,
			},
		},
		{
			name: "Test finalized epoch",
			args: args{
				params:      []gin.Param{{Key: "epoch", Value: "finalized"}},
				expectedErr: nil,
			},
		},
	}
	for _, tt := range tests {
		gin.SetMode(gin.TestMode)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		cache.MustInitIndexerCache()
		c.Params = tt.args.params
		c.Request = &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		defer mockDB.Close()
		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db.IndexerDb = sqlxDB
		epoch, ok := c.Params.Get("epoch")
		if !ok && tt.args.expectedErr == nil {
			t.Errorf("unexpected error while trying to get epoch parameter")
		}

		expectedEpochReturned := int64(0)
		if epoch == "latest" {
			expectedEpochReturned = int64(services.LatestEpoch())
		}

		if epoch == "finalized" {
			expectedEpochReturned = int64(services.LatestFinalizedEpoch())
		}

		blockrows := sqlmock.NewRows([]string{"attestationscount", "attesterslashingscount", "blockroot", "depositscount", "epoch", "eth1data_blockhash", "eth1data_depositcount", "eth1data_depositroot", "exec_base_fee_per_gas", "exec_block_hash", "exec_block_number", "exec_extra_data", "exec_fee_recipient", "exec_gas_limit", "exec_gas_used", "exec_logs_bloom", "exec_parent_hash", "exec_random", "exec_receipts_root", "exec_state_root", "exec_timestamp", "exec_transactions_count", "graffiti", "graffiti_text", "parentroot", "proposer", "proposerslashingscount", "randaoreveal", "signature", "slot", "stateroot", "status", "syncaggregate_bits", "syncaggregate_participation", "syncaggregate_signature", "voluntaryexitscount", "withdrawalcount"}).AddRow(128, 0, "0x1", 0, expectedEpochReturned, "0x1", 312750, "0x1", 15812514105, "0x1", 9300010, "0x1", "0x1", 30000000, 25087947, "0x1", "0x1", "0x1", "0x1", "0x1", 1688647404, 118, "0x1", "Lodestar-v1.9.1/6845eec", "0x1", 412364, 0, "0x1", "0x1", 6011617, "0x1", 1, "0x1", 0.7578125, "0x1", 0, 16)
		mock.ExpectQuery("^SELECT (.+) FROM blocks WHERE").WithArgs(expectedEpochReturned).WillReturnRows(blockrows)
		t.Run(tt.name, func(t *testing.T) {
			ApiEpochSlots(c)
		})

		if w.Code != 200 {
			b, _ := ioutil.ReadAll(w.Body)
			t.Error(w.Code, string(b))
		}
	}
}

func TestApiGlobalParticipationRate(t *testing.T) {
	type args struct {
		expectedErr error
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test ok",
			args: args{
				expectedErr: nil,
			},
		},
	}
	for _, tt := range tests {
		gin.SetMode(gin.TestMode)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		cache.MustInitIndexerCache()
		c.Request = &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		defer mockDB.Close()
		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db.IndexerDb = sqlxDB

		epochrows := sqlmock.NewRows([]string{"globalparticipationrate"}).AddRow(float32(0.9952013510646243))
		mock.ExpectQuery(`SELECT (.+) FROM epochs;`).WillReturnRows(epochrows)
		t.Run(tt.name, func(t *testing.T) {
			ApiGlobalParticipationRate(c)
		})

		if w.Code != 200 {
			b, _ := ioutil.ReadAll(w.Body)
			t.Error(w.Code, string(b))
		}
	}
}

func TestApiValidatorParticipationRate(t *testing.T) {
	utils.Config = &types.Config{}
	utils.Config.Chain.SlotsPerEpoch = 32

	type args struct {
		expectedErr error
		params      []gin.Param
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test ok",
			args: args{
				expectedErr: nil,
				params:      []gin.Param{{Key: "validator_index", Value: "1"}},
			},
		},
	}
	for _, tt := range tests {
		gin.SetMode(gin.TestMode)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		cache.MustInitIndexerCache()
		c.Params = tt.args.params
		c.Request = &http.Request{
			Header: make(http.Header),
			URL:    &url.URL{},
		}

		mockDB, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		defer mockDB.Close()
		sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
		db.IndexerDb = sqlxDB
		valindex, _ := strconv.ParseInt(c.Param("validator_index"), 10, 64)

		rows := sqlmock.NewRows([]string{"missedattestations", "latest_epoch"}).AddRow(82, 188044)
		mock.ExpectQuery(`SELECT (.+) FROM validator_missed_attestations WHERE`).WithArgs(valindex).WillReturnRows(rows)
		t.Run(tt.name, func(t *testing.T) {
			ApiValidatorParticipationRate(c)
		})

		if w.Code != 200 {
			b, _ := ioutil.ReadAll(w.Body)
			t.Error(w.Code, string(b))
		}
	}
}
