package rpc

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	lru "github.com/hashicorp/golang-lru/v2"
)

func mockBeaconHeadersEndpoint(w http.ResponseWriter, r *http.Request) {
	block_id := strings.TrimPrefix(r.URL.Path, "/eth/v1/beacon/headers/")

	sc := http.StatusOK
	m := &StandardBeaconHeaderResponse{}

	if block_id != "head" && block_id != "genesis" && block_id != "finalized" && block_id[:2] != "0x" {
		_, err := strconv.ParseUint(block_id, 10, 32)
		if err != nil {
			sc = http.StatusBadRequest
		}
	} else {
		m.Data.Root = "0x360612c54aa1efcd866537272346e4ab645dcb83d68c74c754cae0320381a640"
		m.Data.Canonical = true
		m.Data.Header.Message.Slot = 6039546
		m.Data.Header.Message.ProposerIndex = 248839
		m.Data.Header.Message.ParentRoot = "0x07046bf69d24d34f754e681223dca53720cdbb28ccb165087e62d6e91e5901a8"
		m.Data.Header.Message.BodyRoot = "0x47b6ed40766f6c3696cad3b3a56d639aa1a608337f874d284100fee248cc8dd8"
		m.Data.Header.Message.StateRoot = "0x82552b85519afa64fce4071cca4743644719a4e88c077caa0b855a9e5ed831ec"
		m.Data.Header.Signature = "0xa8b0712c6efb527a5247b8aa4ea47f189b790281e9d20075e08c9e09984cb145de46a576430a5f1f8c13acb1b6672aa118fa52afc152600ec1e1bc1f6ce00f3265d3bd93dac2b6ef9d4acf12d3851072d9db824fd2541160bae9af642d9bea4d"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(sc)
	json.NewEncoder(w).Encode(m)
}

func mockBeaconStateEndpoint(w http.ResponseWriter, r *http.Request) {
	url_split := strings.Split(strings.TrimPrefix(r.URL.Path, "/eth/v1/beacon/states/"), "/")
	state_id := url_split[0]
	sc := http.StatusOK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(sc)

	switch url_split[1] {
	case "finality_checkpoints":
		m := &StandardFinalityCheckpointsResponse{}
		if state_id != "head" && state_id != "genesis" && state_id != "finalized" && state_id != "justified" && state_id[:2] != "0x" {
			_, err := strconv.ParseUint(state_id, 10, 32)
			if err != nil {
				sc = http.StatusBadRequest
			}
		} else {
			m.Data.PreviousJustified.Epoch = 188743
			m.Data.PreviousJustified.Root = "0xf85d48dc7cea6f2b59825375d2d629515ffa605dd65de072ce563dcc2aaf7116"
			m.Data.CurrentJustified.Epoch = 188744
			m.Data.CurrentJustified.Root = "0xf9205d7291f635eeaaffadedac481f7bb9302900cb348c328880c095a2adac0d"
			m.Data.Finalized.Epoch = 188743
			m.Data.Finalized.Root = "0xf85d48dc7cea6f2b59825375d2d629515ffa605dd65de072ce563dcc2aaf7116"
		}
		json.NewEncoder(w).Encode(m)
	case "committees":
		m := &StandardCommitteesResponse{}
		if state_id != "head" && state_id != "genesis" && state_id != "finalized" && state_id != "justified" && state_id[:2] != "0x" {
			_, err := strconv.ParseUint(state_id, 10, 32)
			if err != nil {
				sc = http.StatusBadRequest
			}
		} else {
			m.Data = []StandardCommitteeEntry{
				{
					Index:      1,
					Slot:       1,
					Validators: []string{"1"},
				},
			}
		}
		json.NewEncoder(w).Encode(m)
	case "sync_committees":
		m := &StandardSyncCommitteesResponse{}
		if state_id != "head" && state_id != "genesis" && state_id != "finalized" && state_id != "justified" && state_id[:2] != "0x" {
			_, err := strconv.ParseUint(state_id, 10, 32)
			if err != nil {
				sc = http.StatusBadRequest
			}
		} else {
			m.Data = StandardSyncCommittee{
				Validators: []string{"1"},
				ValidatorAggregates: [][]string{{
					"1",
				}},
			}
		}
		json.NewEncoder(w).Encode(m)

	default:
		m := make(map[string]interface{})
		json.NewEncoder(w).Encode(m)
	}
}

func mockBeaconBlockEndpoint(w http.ResponseWriter, r *http.Request) {
	url_split := strings.Split(strings.TrimPrefix(r.URL.Path, "/eth/v1/beacon/blocks/"), "/")
	block_id := url_split[0]
	sc := http.StatusOK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(sc)

	switch url_split[1] {
	case "attestations":
		m := &BlockAttestationResponse{}
		if block_id != "head" && block_id != "genesis" && block_id != "finalized" && block_id[:2] != "0x" {
			_, err := strconv.ParseUint(block_id, 10, 32)
			if err != nil {
				sc = http.StatusBadRequest
			}
		} else {
			m.Data = []struct {
				AggregationBits string `json:"aggregation_bits"`
				Signature       string `json:"signature"`
				Data            struct {
					Slot            string `json:"slot"`
					Index           string `json:"index"`
					BeaconBlockRoot string `json:"beacon_block_root"`
					Source          struct {
						Epoch string `json:"epoch"`
						Root  string `json:"root"`
					} `json:"source"`
					Target struct {
						Epoch string `json:"epoch"`
						Root  string `json:"root"`
					} `json:"target"`
				}
			}{{
				AggregationBits: "0x01",
				Signature:       "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
			}}
			m.Data[0].Data.Slot = "1"
			m.Data[0].Data.Index = "1"
			m.Data[0].Data.BeaconBlockRoot = "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
			m.Data[0].Data.Source.Epoch = "1"
			m.Data[0].Data.Source.Root = "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
			m.Data[0].Data.Target.Epoch = "1"
			m.Data[0].Data.Target.Root = "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
		}
		json.NewEncoder(w).Encode(m)
	default:
		m := make(map[string]interface{})
		json.NewEncoder(w).Encode(m)
	}
}

func mockValidatorDutiesEndpoint(w http.ResponseWriter, r *http.Request) {
	url_split := strings.Split(strings.TrimPrefix(r.URL.Path, "/eth/v1/validator/duties/"), "/")
	role := url_split[0]
	epoch := url_split[1]
	sc := http.StatusOK
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(sc)

	switch role {
	case "proposer":
		m := &StandardProposerDutiesResponse{}
		_, err := strconv.ParseUint(epoch, 10, 32)
		if err != nil {
			sc = http.StatusBadRequest
		} else {
			m.DependentRoot = "0xad73d27b85980c169d2682de8c3371cafb49bfc2eea2eadc69eb81b7489b5ef7"
			m.Data = []StandardProposerDuty{{
				Pubkey:         "0x86f8cb63852842b6b2d19aad004debf95dd99404dde334f074c9fa4d415ef0957db6775cea515767b3882e6452cb72be",
				Slot:           6039520,
				ValidatorIndex: 7579,
			}}
		}
		json.NewEncoder(w).Encode(m)
	default:
		m := make(map[string]interface{})
		json.NewEncoder(w).Encode(m)
	}
}

func TestBeaconClient_GetChainHead(t *testing.T) {
	type client struct {
		endpoint            string
		assignmentsCache    *lru.Cache[uint64, any]
		assignmentsCacheMux *sync.Mutex
		signer              gtypes.Signer
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/eth/v1/beacon/headers/head":
			mockBeaconHeadersEndpoint(w, r)
		case "/eth/v1/beacon/states/6039546/finality_checkpoints":
			mockBeaconStateEndpoint(w, r)
		default:
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}))
	utils.Config = &types.Config{}
	utils.Config.Chain.DepositChainID = 5
	utils.Config.Chain.SlotsPerEpoch = 32
	chainID := new(big.Int).SetUint64(utils.Config.Chain.DepositChainID)
	assignmentsCache, _ := lru.New[uint64, any](10)
	tests := []struct {
		name    string
		client  client
		want    *types.ChainHead
		wantErr bool
	}{
		{
			name: "test ok",
			client: client{
				endpoint:            mockServer.URL,
				signer:              gtypes.NewLondonSigner(chainID),
				assignmentsCacheMux: &sync.Mutex{},
				assignmentsCache:    assignmentsCache,
			},
			want: &types.ChainHead{
				HeadSlot:                   6039546,
				HeadEpoch:                  188735,
				HeadBlockRoot:              []uint8{54, 6, 18, 197, 74, 161, 239, 205, 134, 101, 55, 39, 35, 70, 228, 171, 100, 93, 203, 131, 214, 140, 116, 199, 84, 202, 224, 50, 3, 129, 166, 64},
				FinalizedSlot:              0,
				FinalizedEpoch:             0,
				FinalizedBlockRoot:         []uint8{},
				JustifiedSlot:              0,
				JustifiedEpoch:             0,
				JustifiedBlockRoot:         []uint8{},
				PreviousJustifiedSlot:      0,
				PreviousJustifiedEpoch:     0,
				PreviousJustifiedBlockRoot: []uint8{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beacon := &BeaconClient{
				endpoint:            tt.client.endpoint,
				assignmentsCache:    tt.client.assignmentsCache,
				assignmentsCacheMux: tt.client.assignmentsCacheMux,
				signer:              tt.client.signer,
			}
			got, err := beacon.GetChainHead()
			fmt.Print(got)
			if (err != nil) != tt.wantErr {
				t.Errorf("BeaconClient.GetChainHead() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BeaconClient.GetChainHead() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBeaconClient_GetEpochAssignments(t *testing.T) {
	type client struct {
		endpoint            string
		assignmentsCache    *lru.Cache[uint64, any]
		assignmentsCacheMux *sync.Mutex
		signer              gtypes.Signer
	}
	type args struct {
		epoch uint64
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/eth/v1/beacon/headers/0xad73d27b85980c169d2682de8c3371cafb49bfc2eea2eadc69eb81b7489b5ef7":
			mockBeaconHeadersEndpoint(w, r)
		case "/eth/v1/validator/duties/proposer/188735":
			mockValidatorDutiesEndpoint(w, r)
		case "/eth/v1/beacon/states/0x82552b85519afa64fce4071cca4743644719a4e88c077caa0b855a9e5ed831ec/committees":
			mockBeaconStateEndpoint(w, r)
		case "/eth/v1/beacon/states/0x82552b85519afa64fce4071cca4743644719a4e88c077caa0b855a9e5ed831ec/sync_committees":
			mockBeaconStateEndpoint(w, r)
		default:
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}))
	utils.Config = &types.Config{}
	utils.Config.Chain.DepositChainID = 5
	utils.Config.Chain.SlotsPerEpoch = 32
	chainID := new(big.Int).SetUint64(utils.Config.Chain.DepositChainID)
	assignmentsCache, _ := lru.New[uint64, any](10)

	tests := []struct {
		name    string
		client  client
		args    args
		want    *types.EpochAssignments
		wantErr bool
	}{
		{
			name: "test ok",
			client: client{
				endpoint:            mockServer.URL,
				signer:              gtypes.NewLondonSigner(chainID),
				assignmentsCacheMux: &sync.Mutex{},
				assignmentsCache:    assignmentsCache,
			},
			want: &types.EpochAssignments{
				ProposerAssignments: map[uint64]uint64{6039520: 7579},
				AttestorAssignments: map[string]uint64{"1-1-0": 1},
				SyncAssignments:     []uint64{1},
			},
			wantErr: false,
			args: args{
				epoch: 188735,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beacon := &BeaconClient{
				endpoint:            tt.client.endpoint,
				assignmentsCache:    tt.client.assignmentsCache,
				assignmentsCacheMux: tt.client.assignmentsCacheMux,
				signer:              tt.client.signer,
			}
			got, err := beacon.GetEpochAssignments(tt.args.epoch)
			if (err != nil) != tt.wantErr {
				t.Errorf("BeaconClient.GetEpochAssignments() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BeaconClient.GetEpochAssignments() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBeaconClient_GetValidatorParticipation(t *testing.T) {
	type client struct {
		endpoint            string
		assignmentsCache    *lru.Cache[uint64, any]
		assignmentsCacheMux *sync.Mutex
		signer              gtypes.Signer
	}
	type args struct {
		epoch         uint64
		validatorData []*types.Validator
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimSpace(r.URL.Path) {
		case "/eth/v1/beacon/headers/head":
			mockBeaconHeadersEndpoint(w, r)
		case "/eth/v1/beacon/states/6039546/finality_checkpoints":
			mockBeaconStateEndpoint(w, r)
		case "/eth/v1/beacon/blocks/6039520/attestations":
			mockBeaconBlockEndpoint(w, r)
		default:
			http.NotFoundHandler().ServeHTTP(w, r)
		}
	}))

	utils.Config = &types.Config{}
	utils.Config.Chain.DepositChainID = 5
	utils.Config.Chain.SlotsPerEpoch = 32
	chainID := new(big.Int).SetUint64(utils.Config.Chain.DepositChainID)
	assignmentsCache, _ := lru.New[uint64, any](10)

	tests := []struct {
		name    string
		client  client
		args    args
		want    *types.ValidatorParticipation
		wantErr bool
	}{
		{
			name: "test ok",
			client: client{
				endpoint:            mockServer.URL,
				signer:              gtypes.NewLondonSigner(chainID),
				assignmentsCacheMux: &sync.Mutex{},
				assignmentsCache:    assignmentsCache,
			},
			args: args{
				epoch:         188734,
				validatorData: []*types.Validator{{}},
			},
			want: &types.ValidatorParticipation{
				Epoch:                   188734,
				GlobalParticipationRate: 0,
				VotedEther:              0,
				EligibleEther:           0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beacon := &BeaconClient{
				endpoint:            tt.client.endpoint,
				assignmentsCache:    tt.client.assignmentsCache,
				assignmentsCacheMux: tt.client.assignmentsCacheMux,
				signer:              tt.client.signer,
			}
			got, err := beacon.GetValidatorParticipation(tt.args.epoch, tt.args.validatorData)
			if (err != nil) != tt.wantErr {
				t.Errorf("BeaconClient.GetValidatorParticipation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BeaconClient.GetValidatorParticipation() = %v, want %v", got, tt.want)
			}
		})
	}
}
