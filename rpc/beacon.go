package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/Prajjawalk/beacon-light-indexer/utils"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New().WithField("module", "rpc")

var BeaconLatestHeadEpoch uint64 = 0

type BeaconClient struct {
	endpoint            string
	assignmentsCache    *lru.Cache[uint64, any]
	assignmentsCacheMux *sync.Mutex
	signer              gtypes.Signer
}

func NewBeaconClient(endpoint string, chainID *big.Int) *BeaconClient {
	signer := gtypes.NewLondonSigner(chainID)
	client := &BeaconClient{
		endpoint:            endpoint,
		assignmentsCacheMux: &sync.Mutex{},
		signer:              signer,
	}
	client.assignmentsCache, _ = lru.New[uint64, any](10)
	return client
}

// GetChainHead gets the chain head from Beacon Node
func (beacon *BeaconClient) GetChainHead() (*types.ChainHead, error) {
	headResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/headers/head", beacon.endpoint))
	if err != nil {
		return nil, fmt.Errorf("error retrieving chain head: %v", err)
	}

	var parsedHead StandardBeaconHeaderResponse
	err = json.Unmarshal(headResp, &parsedHead)
	if err != nil {
		return nil, fmt.Errorf("error parsing chain head: %v", err)
	}

	id := fmt.Sprintf("%d", parsedHead.Data.Header.Message.Slot)
	if parsedHead.Data.Header.Message.Slot == 0 {
		id = "genesis"
	}
	finalityResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/states/%s/finality_checkpoints", beacon.endpoint, id))
	if err != nil {
		return nil, fmt.Errorf("error retrieving finality checkpoints of head %v: %v", id, err)
	}

	var parsedFinality StandardFinalityCheckpointsResponse
	err = json.Unmarshal(finalityResp, &parsedFinality)
	if err != nil {
		return nil, fmt.Errorf("error parsing finality checkpoints of head: %v", err)
	}

	return &types.ChainHead{
		HeadSlot:                   uint64(parsedHead.Data.Header.Message.Slot),
		HeadEpoch:                  uint64(parsedHead.Data.Header.Message.Slot) / utils.Config.Chain.SlotsPerEpoch,
		HeadBlockRoot:              utils.MustParseHex(parsedHead.Data.Root),
		FinalizedSlot:              uint64(parsedFinality.Data.Finalized.Epoch) * utils.Config.Chain.SlotsPerEpoch,
		FinalizedEpoch:             uint64(parsedFinality.Data.Finalized.Epoch),
		FinalizedBlockRoot:         utils.MustParseHex(parsedFinality.Data.Finalized.Root),
		JustifiedSlot:              uint64(parsedFinality.Data.CurrentJustified.Epoch) * utils.Config.Chain.SlotsPerEpoch,
		JustifiedEpoch:             uint64(parsedFinality.Data.CurrentJustified.Epoch),
		JustifiedBlockRoot:         utils.MustParseHex(parsedFinality.Data.CurrentJustified.Root),
		PreviousJustifiedSlot:      uint64(parsedFinality.Data.PreviousJustified.Epoch) * utils.Config.Chain.SlotsPerEpoch,
		PreviousJustifiedEpoch:     uint64(parsedFinality.Data.PreviousJustified.Epoch),
		PreviousJustifiedBlockRoot: utils.MustParseHex(parsedFinality.Data.PreviousJustified.Root),
	}, nil
}

// GetEpochAssignments will get the epoch assignments from Beacon RPC api
func (beacon *BeaconClient) GetEpochAssignments(epoch uint64) (*types.EpochAssignments, error) {
	beacon.assignmentsCacheMux.Lock()
	defer beacon.assignmentsCacheMux.Unlock()

	var err error

	cachedValue, found := beacon.assignmentsCache.Get(epoch)
	if found {
		return cachedValue.(*types.EpochAssignments), nil
	}

	proposerResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", beacon.endpoint, epoch))
	if err != nil {
		return nil, fmt.Errorf("error retrieving proposer duties: %v", err)
	}
	var parsedProposerResponse StandardProposerDutiesResponse
	err = json.Unmarshal(proposerResp, &parsedProposerResponse)
	if err != nil {
		return nil, fmt.Errorf("error parsing proposer duties: %v", err)
	}

	// fetch the block root that the proposer data is dependent on
	headerResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/headers/%s", beacon.endpoint, parsedProposerResponse.DependentRoot))
	if err != nil {
		return nil, fmt.Errorf("error retrieving chain header: %v", err)
	}
	var parsedHeader StandardBeaconHeaderResponse
	err = json.Unmarshal(headerResp, &parsedHeader)
	if err != nil {
		return nil, fmt.Errorf("error parsing chain header: %v", err)
	}
	depStateRoot := parsedHeader.Data.Header.Message.StateRoot

	assignments := &types.EpochAssignments{
		ProposerAssignments: make(map[uint64]uint64),
		AttestorAssignments: make(map[string]uint64),
	}

	// Now use the state root to make a consistent committee query
	committeesResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/states/%s/committees?epoch=%d", beacon.endpoint, depStateRoot, epoch))

	if err != nil {
		return nil, fmt.Errorf("error retrieving committees data: %w", err)
	}
	var parsedCommittees StandardCommitteesResponse
	err = json.Unmarshal(committeesResp, &parsedCommittees)
	if err != nil {
		return nil, fmt.Errorf("error parsing committees data: %w", err)
	}

	// propose
	for _, duty := range parsedProposerResponse.Data {
		assignments.ProposerAssignments[uint64(duty.Slot)] = uint64(duty.ValidatorIndex)
	}

	// attest
	for _, committee := range parsedCommittees.Data {
		for i, valIndex := range committee.Validators {
			valIndexU64, err := strconv.ParseUint(valIndex, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("epoch %d committee %d index %d has bad validator index %q", epoch, committee.Index, i, valIndex)
			}
			k := utils.FormatAttestorAssignmentKey(uint64(committee.Slot), uint64(committee.Index), uint64(i))
			assignments.AttestorAssignments[k] = valIndexU64
		}
	}

	if epoch >= utils.Config.Chain.AltairForkEpoch {
		syncCommitteeState := depStateRoot
		if epoch == utils.Config.Chain.AltairForkEpoch {
			syncCommitteeState = fmt.Sprintf("%d", utils.Config.Chain.AltairForkEpoch*utils.Config.Chain.SlotsPerEpoch)
		}
		parsedSyncCommittees, err := beacon.GetSyncCommittee(syncCommitteeState, epoch)
		if err != nil {
			return nil, err
		}
		assignments.SyncAssignments = make([]uint64, len(parsedSyncCommittees.Validators))

		// sync
		for i, valIndexStr := range parsedSyncCommittees.Validators {
			valIndexU64, err := strconv.ParseUint(valIndexStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("in sync_committee for epoch %d validator %d has bad validator index: %q", epoch, i, valIndexStr)
			}
			assignments.SyncAssignments[i] = valIndexU64
		}
	}

	if len(assignments.AttestorAssignments) > 0 && len(assignments.ProposerAssignments) > 0 {
		beacon.assignmentsCache.Add(epoch, assignments)
	}

	return assignments, nil
}

// GetEpochData will get the epoch data from Beacon RPC api
func (beacon *BeaconClient) GetEpochData(epoch uint64, skipHistoricBalances bool) (*types.EpochData, error) {
	wg := &sync.WaitGroup{}
	mux := &sync.Mutex{}

	data := &types.EpochData{}
	data.Epoch = epoch

	validatorsResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/states/%d/validators", beacon.endpoint, epoch*utils.Config.Chain.SlotsPerEpoch))
	if err != nil && epoch == 0 {
		validatorsResp, err = beacon.get(fmt.Sprintf("%s/eth/v1/beacon/states/%v/validators", beacon.endpoint, "genesis"))
		if err != nil {
			return nil, fmt.Errorf("error retrieving validators for genesis: %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving validators for epoch %v: %v", epoch, err)
	}

	var parsedValidators StandardValidatorsResponse
	err = json.Unmarshal(validatorsResp, &parsedValidators)
	if err != nil {
		return nil, fmt.Errorf("error parsing epoch validators: %v", err)
	}

	for _, validator := range parsedValidators.Data {
		data.Validators = append(data.Validators, &types.Validator{
			Index:                      uint64(validator.Index),
			PublicKey:                  utils.MustParseHex(validator.Validator.Pubkey),
			WithdrawalCredentials:      utils.MustParseHex(validator.Validator.WithdrawalCredentials),
			Balance:                    uint64(validator.Balance),
			EffectiveBalance:           uint64(validator.Validator.EffectiveBalance),
			Slashed:                    validator.Validator.Slashed,
			ActivationEligibilityEpoch: uint64(validator.Validator.ActivationEligibilityEpoch),
			ActivationEpoch:            uint64(validator.Validator.ActivationEpoch),
			ExitEpoch:                  uint64(validator.Validator.ExitEpoch),
			WithdrawableEpoch:          uint64(validator.Validator.WithdrawableEpoch),
			Status:                     validator.Status,
		})
	}

	logger.Printf("retrieved data for %v validators for epoch %v", len(data.Validators), epoch)

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		data.ValidatorAssignmentes, err = beacon.GetEpochAssignments(epoch)
		if err != nil {
			logrus.Errorf("error retrieving assignments for epoch %v: %v", epoch, err)
			return
		}
		logger.Printf("retrieved validator assignment data for epoch %v", epoch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		data.EpochParticipationStats, err = beacon.GetValidatorParticipation(epoch, data.Validators)
		if err != nil {
			if strings.HasSuffix(err.Error(), "can't be retrieved as it hasn't finished yet") {
				logger.Warnf("error retrieving epoch participation statistics for epoch %v: %v", epoch, err)
			} else {
				logger.Errorf("error retrieving epoch participation statistics for epoch %v: %v", epoch, err)
			}
			data.EpochParticipationStats = &types.ValidatorParticipation{
				Epoch:                   epoch,
				GlobalParticipationRate: 1.0,
				VotedEther:              0,
				EligibleEther:           0,
			}
		}
	}()

	if utils.Config.IndexBlocks {
		// Retrieve all blocks for the epoch
		data.Blocks = make(map[uint64]map[string]*types.Block)

		for slot := epoch * utils.Config.Chain.SlotsPerEpoch; slot <= (epoch+1)*utils.Config.Chain.SlotsPerEpoch-1; slot++ {
			if slot != 0 && utils.SlotToTime(slot).After(time.Now()) { // don't export slots that have not occured yet
				continue
			}
			wg.Add(1)
			go func(slot uint64) {
				defer wg.Done()
				blocks, err := beacon.GetBlocksBySlot(slot)

				if err != nil {
					logger.Errorf("error retrieving blocks for slot %v: %v", slot, err)
					return
				}

				for _, block := range blocks {
					mux.Lock()
					if data.Blocks[block.Slot] == nil {
						data.Blocks[block.Slot] = make(map[string]*types.Block)
					}
					data.Blocks[block.Slot][fmt.Sprintf("%x", block.BlockRoot)] = block
					mux.Unlock()
				}
			}(slot)
		}
		wg.Wait()
		logger.Printf("retrieved %v blocks for epoch %v", len(data.Blocks), epoch)

		if data.ValidatorAssignmentes == nil {
			return data, fmt.Errorf("no assignments for epoch %v", epoch)
		}

		// Fill up missed and scheduled blocks
		for slot, proposer := range data.ValidatorAssignmentes.ProposerAssignments {
			_, found := data.Blocks[slot]
			if !found {
				// Proposer was assigned but did not yet propose a block
				data.Blocks[slot] = make(map[string]*types.Block)
				data.Blocks[slot]["0x0"] = &types.Block{
					Status:            0,
					Canonical:         true,
					Proposer:          proposer,
					BlockRoot:         []byte{0x0},
					Slot:              slot,
					ParentRoot:        []byte{},
					StateRoot:         []byte{},
					Signature:         []byte{},
					RandaoReveal:      []byte{},
					Graffiti:          []byte{},
					BodyRoot:          []byte{},
					Eth1Data:          &types.Eth1Data{},
					ProposerSlashings: make([]*types.ProposerSlashing, 0),
					AttesterSlashings: make([]*types.AttesterSlashing, 0),
					Attestations:      make([]*types.Attestation, 0),
					Deposits:          make([]*types.Deposit, 0),
					VoluntaryExits:    make([]*types.VoluntaryExit, 0),
					SyncAggregate:     nil,
				}

				if utils.SlotToTime(slot).After(time.Now().Add(time.Second * -4)) {
					// Block is in the future, set status to scheduled
					data.Blocks[slot]["0x0"].Status = 0
					data.Blocks[slot]["0x0"].BlockRoot = []byte{0x0}
				} else {
					// Block is in the past, set status to missed
					data.Blocks[slot]["0x0"].Status = 2
					data.Blocks[slot]["0x0"].BlockRoot = []byte{0x1}
				}
			}
		}
	} else {
		wg.Wait()
	}

	return data, nil
}

// GetBlocksBySlot will get the blocks by slot from Beacon RPC api
func (beacon *BeaconClient) GetBlocksBySlot(slot uint64) ([]*types.Block, error) {
	var parsedHeaders *StandardBeaconHeaderResponse

	resHeaders, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/headers/%d", beacon.endpoint, slot))

	if err != nil && slot == 0 {
		headResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/headers", beacon.endpoint))
		if err != nil {
			return nil, fmt.Errorf("error retrieving chain head: %v", err)
		}

		var parsedHeader StandardBeaconHeadersResponse
		err = json.Unmarshal(headResp, &parsedHeader)
		if err != nil {
			return nil, fmt.Errorf("error parsing chain head: %v", err)
		}

		if len(parsedHeader.Data) == 0 {
			return nil, fmt.Errorf("error no headers available")
		}

		parsedHeaders = &StandardBeaconHeaderResponse{
			Data: parsedHeader.Data[len(parsedHeader.Data)-1],
		}

	} else if err != nil {
		if err == errNotFound {
			// no block found
			return []*types.Block{}, nil
		}
		return nil, fmt.Errorf("error retrieving headers at slot %v: %v", slot, err)
	}

	if parsedHeaders == nil {
		err = json.Unmarshal(resHeaders, &parsedHeaders)
		if err != nil {
			return nil, fmt.Errorf("error parsing header-response at slot %v: %v", slot, err)
		}
	}

	resp, err := beacon.get(fmt.Sprintf("%s/eth/v2/beacon/blocks/%s", beacon.endpoint, parsedHeaders.Data.Root))

	if err != nil && slot == 0 {
		return nil, fmt.Errorf("error retrieving block data at slot %v: %v", slot, err)
	}

	var parsedResponse StandardV2BlockResponse
	err = json.Unmarshal(resp, &parsedResponse)
	if err != nil {
		logger.Errorf("error parsing block data at slot %v: %v", slot, err)
		return nil, fmt.Errorf("error parsing block-response at slot %v: %v", slot, err)
	}

	block, err := beacon.blockFromResponse(parsedHeaders, &parsedResponse)
	if err != nil {
		return nil, err
	}
	return []*types.Block{block}, nil
}

func (beacon *BeaconClient) blockFromResponse(parsedHeaders *StandardBeaconHeaderResponse, parsedResponse *StandardV2BlockResponse) (*types.Block, error) {
	parsedBlock := parsedResponse.Data
	slot := uint64(parsedHeaders.Data.Header.Message.Slot)
	block := &types.Block{
		Status:       1,
		Canonical:    parsedHeaders.Data.Canonical,
		Proposer:     uint64(parsedBlock.Message.ProposerIndex),
		BlockRoot:    utils.MustParseHex(parsedHeaders.Data.Root),
		Slot:         slot,
		ParentRoot:   utils.MustParseHex(parsedBlock.Message.ParentRoot),
		StateRoot:    utils.MustParseHex(parsedBlock.Message.StateRoot),
		Signature:    parsedBlock.Signature,
		RandaoReveal: utils.MustParseHex(parsedBlock.Message.Body.RandaoReveal),
		Graffiti:     utils.MustParseHex(parsedBlock.Message.Body.Graffiti),
		Eth1Data: &types.Eth1Data{
			DepositRoot:  utils.MustParseHex(parsedBlock.Message.Body.Eth1Data.DepositRoot),
			DepositCount: uint64(parsedBlock.Message.Body.Eth1Data.DepositCount),
			BlockHash:    utils.MustParseHex(parsedBlock.Message.Body.Eth1Data.BlockHash),
		},
		ProposerSlashings:          make([]*types.ProposerSlashing, len(parsedBlock.Message.Body.ProposerSlashings)),
		AttesterSlashings:          make([]*types.AttesterSlashing, len(parsedBlock.Message.Body.AttesterSlashings)),
		Attestations:               make([]*types.Attestation, len(parsedBlock.Message.Body.Attestations)),
		Deposits:                   make([]*types.Deposit, len(parsedBlock.Message.Body.Deposits)),
		VoluntaryExits:             make([]*types.VoluntaryExit, len(parsedBlock.Message.Body.VoluntaryExits)),
		SignedBLSToExecutionChange: make([]*types.SignedBLSToExecutionChange, len(parsedBlock.Message.Body.SignedBLSToExecutionChange)),
	}

	epochAssignments, err := beacon.GetEpochAssignments(slot / utils.Config.Chain.SlotsPerEpoch)
	if err != nil {
		return nil, err
	}

	if agg := parsedBlock.Message.Body.SyncAggregate; agg != nil {
		bits := utils.MustParseHex(agg.SyncCommitteeBits)

		if utils.Config.Chain.SyncCommitteeSize != uint64(len(bits)*8) {
			return nil, fmt.Errorf("sync-aggregate-bits-size does not match sync-committee-size: %v != %v", len(bits)*8, utils.Config.Chain.SyncCommitteeSize)
		}

		block.SyncAggregate = &types.SyncAggregate{
			SyncCommitteeValidators:    epochAssignments.SyncAssignments,
			SyncCommitteeBits:          bits,
			SyncAggregateParticipation: syncCommitteeParticipation(bits),
			SyncCommitteeSignature:     utils.MustParseHex(agg.SyncCommitteeSignature),
		}
	}

	if payload := parsedBlock.Message.Body.ExecutionPayload; payload != nil && !bytes.Equal(payload.ParentHash, make([]byte, 32)) {
		txs := make([]*types.Transaction, 0, len(payload.Transactions))
		for i, rawTx := range payload.Transactions {
			tx := &types.Transaction{Raw: rawTx}
			var decTx gtypes.Transaction
			if err := decTx.UnmarshalBinary(rawTx); err != nil {
				return nil, fmt.Errorf("error parsing tx %d block %x: %v", i, payload.BlockHash, err)
			} else {
				h := decTx.Hash()
				tx.TxHash = h[:]
				tx.AccountNonce = decTx.Nonce()
				// big endian
				tx.Price = decTx.GasPrice().Bytes()
				tx.GasLimit = decTx.Gas()
				sender, err := beacon.signer.Sender(&decTx)
				if err != nil {
					return nil, fmt.Errorf("transaction with invalid sender (tx hash: %x): %v", h, err)
				}
				tx.Sender = sender.Bytes()
				if v := decTx.To(); v != nil {
					tx.Recipient = v.Bytes()
				} else {
					tx.Recipient = []byte{}
				}
				tx.Amount = decTx.Value().Bytes()
				tx.Payload = decTx.Data()
				tx.MaxPriorityFeePerGas = decTx.GasTipCap().Uint64()
				tx.MaxFeePerGas = decTx.GasFeeCap().Uint64()
			}
			txs = append(txs, tx)
		}
		withdrawals := make([]*types.Withdrawals, 0, len(payload.Withdrawals))
		for _, w := range payload.Withdrawals {
			withdrawals = append(withdrawals, &types.Withdrawals{
				Index:          uint64(w.Index),
				ValidatorIndex: uint64(w.ValidatorIndex),
				Address:        w.Address,
				Amount:         uint64(w.Amount),
			})
		}

		block.ExecutionPayload = &types.ExecutionPayload{
			ParentHash:    payload.ParentHash,
			FeeRecipient:  payload.FeeRecipient,
			StateRoot:     payload.StateRoot,
			ReceiptsRoot:  payload.ReceiptsRoot,
			LogsBloom:     payload.LogsBloom,
			Random:        payload.PrevRandao,
			BlockNumber:   uint64(payload.BlockNumber),
			GasLimit:      uint64(payload.GasLimit),
			GasUsed:       uint64(payload.GasUsed),
			Timestamp:     uint64(payload.Timestamp),
			ExtraData:     payload.ExtraData,
			BaseFeePerGas: uint64(payload.BaseFeePerGas),
			BlockHash:     payload.BlockHash,
			Transactions:  txs,
			Withdrawals:   withdrawals,
		}
	}

	if block.Eth1Data.DepositCount > 2147483647 {
		block.Eth1Data.DepositCount = 0
	}

	for i, proposerSlashing := range parsedBlock.Message.Body.ProposerSlashings {
		block.ProposerSlashings[i] = &types.ProposerSlashing{
			ProposerIndex: uint64(proposerSlashing.SignedHeader1.Message.ProposerIndex),
			Header1: &types.Block{
				Slot:       uint64(proposerSlashing.SignedHeader1.Message.Slot),
				ParentRoot: utils.MustParseHex(proposerSlashing.SignedHeader1.Message.ParentRoot),
				StateRoot:  utils.MustParseHex(proposerSlashing.SignedHeader1.Message.StateRoot),
				Signature:  utils.MustParseHex(proposerSlashing.SignedHeader1.Signature),
				BodyRoot:   utils.MustParseHex(proposerSlashing.SignedHeader1.Message.BodyRoot),
			},
			Header2: &types.Block{
				Slot:       uint64(proposerSlashing.SignedHeader2.Message.Slot),
				ParentRoot: utils.MustParseHex(proposerSlashing.SignedHeader2.Message.ParentRoot),
				StateRoot:  utils.MustParseHex(proposerSlashing.SignedHeader2.Message.StateRoot),
				Signature:  utils.MustParseHex(proposerSlashing.SignedHeader2.Signature),
				BodyRoot:   utils.MustParseHex(proposerSlashing.SignedHeader2.Message.BodyRoot),
			},
		}
	}

	for i, attesterSlashing := range parsedBlock.Message.Body.AttesterSlashings {
		block.AttesterSlashings[i] = &types.AttesterSlashing{
			Attestation1: &types.IndexedAttestation{
				Data: &types.AttestationData{
					Slot:            uint64(attesterSlashing.Attestation1.Data.Slot),
					CommitteeIndex:  uint64(attesterSlashing.Attestation1.Data.Index),
					BeaconBlockRoot: utils.MustParseHex(attesterSlashing.Attestation1.Data.BeaconBlockRoot),
					Source: &types.Checkpoint{
						Epoch: uint64(attesterSlashing.Attestation1.Data.Source.Epoch),
						Root:  utils.MustParseHex(attesterSlashing.Attestation1.Data.Source.Root),
					},
					Target: &types.Checkpoint{
						Epoch: uint64(attesterSlashing.Attestation1.Data.Target.Epoch),
						Root:  utils.MustParseHex(attesterSlashing.Attestation1.Data.Target.Root),
					},
				},
				Signature:        utils.MustParseHex(attesterSlashing.Attestation1.Signature),
				AttestingIndices: uint64List(attesterSlashing.Attestation1.AttestingIndices),
			},
			Attestation2: &types.IndexedAttestation{
				Data: &types.AttestationData{
					Slot:            uint64(attesterSlashing.Attestation2.Data.Slot),
					CommitteeIndex:  uint64(attesterSlashing.Attestation2.Data.Index),
					BeaconBlockRoot: utils.MustParseHex(attesterSlashing.Attestation2.Data.BeaconBlockRoot),
					Source: &types.Checkpoint{
						Epoch: uint64(attesterSlashing.Attestation2.Data.Source.Epoch),
						Root:  utils.MustParseHex(attesterSlashing.Attestation2.Data.Source.Root),
					},
					Target: &types.Checkpoint{
						Epoch: uint64(attesterSlashing.Attestation2.Data.Target.Epoch),
						Root:  utils.MustParseHex(attesterSlashing.Attestation2.Data.Target.Root),
					},
				},
				Signature:        utils.MustParseHex(attesterSlashing.Attestation2.Signature),
				AttestingIndices: uint64List(attesterSlashing.Attestation2.AttestingIndices),
			},
		}
	}

	for i, attestation := range parsedBlock.Message.Body.Attestations {
		a := &types.Attestation{
			AggregationBits: utils.MustParseHex(attestation.AggregationBits),
			Attesters:       []uint64{},
			Data: &types.AttestationData{
				Slot:            uint64(attestation.Data.Slot),
				CommitteeIndex:  uint64(attestation.Data.Index),
				BeaconBlockRoot: utils.MustParseHex(attestation.Data.BeaconBlockRoot),
				Source: &types.Checkpoint{
					Epoch: uint64(attestation.Data.Source.Epoch),
					Root:  utils.MustParseHex(attestation.Data.Source.Root),
				},
				Target: &types.Checkpoint{
					Epoch: uint64(attestation.Data.Target.Epoch),
					Root:  utils.MustParseHex(attestation.Data.Target.Root),
				},
			},
			Signature: utils.MustParseHex(attestation.Signature),
		}

		aggregationBits := bitfield.Bitlist(a.AggregationBits)
		assignments, err := beacon.GetEpochAssignments(a.Data.Slot / utils.Config.Chain.SlotsPerEpoch)
		if err != nil {
			return nil, fmt.Errorf("error receiving epoch assignment for epoch %v: %v", a.Data.Slot/utils.Config.Chain.SlotsPerEpoch, err)
		}

		for i := uint64(0); i < aggregationBits.Len(); i++ {
			if aggregationBits.BitAt(i) {
				validator, found := assignments.AttestorAssignments[utils.FormatAttestorAssignmentKey(a.Data.Slot, a.Data.CommitteeIndex, i)]
				if !found { // This should never happen!
					validator = 0
					logger.Errorf("error retrieving assigned validator for attestation %v of block %v for slot %v committee index %v member index %v", i, block.Slot, a.Data.Slot, a.Data.CommitteeIndex, i)
				}
				a.Attesters = append(a.Attesters, validator)
			}
		}

		block.Attestations[i] = a
	}

	for i, deposit := range parsedBlock.Message.Body.Deposits {
		d := &types.Deposit{
			Proof:                 nil,
			PublicKey:             utils.MustParseHex(deposit.Data.Pubkey),
			WithdrawalCredentials: utils.MustParseHex(deposit.Data.WithdrawalCredentials),
			Amount:                uint64(deposit.Data.Amount),
			Signature:             utils.MustParseHex(deposit.Data.Signature),
		}

		block.Deposits[i] = d
	}

	for i, voluntaryExit := range parsedBlock.Message.Body.VoluntaryExits {
		block.VoluntaryExits[i] = &types.VoluntaryExit{
			Epoch:          uint64(voluntaryExit.Message.Epoch),
			ValidatorIndex: uint64(voluntaryExit.Message.ValidatorIndex),
			Signature:      utils.MustParseHex(voluntaryExit.Signature),
		}
	}

	for i, blsChange := range parsedBlock.Message.Body.SignedBLSToExecutionChange {
		block.SignedBLSToExecutionChange[i] = &types.SignedBLSToExecutionChange{
			Message: types.BLSToExecutionChange{
				Validatorindex: uint64(blsChange.Message.ValidatorIndex),
				BlsPubkey:      blsChange.Message.FromBlsPubkey,
				Address:        blsChange.Message.ToExecutionAddress,
			},
			Signature: blsChange.Signature,
		}
	}

	return block, nil
}

func syncCommitteeParticipation(bits []byte) float64 {
	participating := 0
	for i := 0; i < int(utils.Config.Chain.SyncCommitteeSize); i++ {
		if utils.BitAtVector(bits, i) {
			participating++
		}
	}
	return float64(participating) / float64(utils.Config.Chain.SyncCommitteeSize)
}

func (beacon *BeaconClient) GetSyncCommittee(stateID string, epoch uint64) (*StandardSyncCommittee, error) {
	syncCommitteesResp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/states/%s/sync_committees?epoch=%d", beacon.endpoint, stateID, epoch))
	if err != nil {
		return nil, fmt.Errorf("error retrieving sync_committees for epoch %v (state: %v): %w", epoch, stateID, err)
	}
	var parsedSyncCommittees StandardSyncCommitteesResponse
	err = json.Unmarshal(syncCommitteesResp, &parsedSyncCommittees)
	if err != nil {
		return nil, fmt.Errorf("error parsing sync_committees data for epoch %v (state: %v): %w", epoch, stateID, err)
	}
	return &parsedSyncCommittees.Data, nil
}

// GetValidatorParticipation will get the validator participation from the Beacon RPC api
func (beacon *BeaconClient) GetValidatorParticipation(epoch uint64, validatorData []*types.Validator) (*types.ValidatorParticipation, error) {
	if BeaconLatestHeadEpoch == 0 || epoch >= BeaconLatestHeadEpoch-1 {
		head, err := beacon.GetChainHead()
		if err != nil {
			return nil, err
		}
		logger.Infof("Updating BeaconLatestHeadEpoch to %v", head.HeadEpoch)
		BeaconLatestHeadEpoch = head.HeadEpoch
	}

	if epoch > BeaconLatestHeadEpoch {
		return nil, fmt.Errorf("epoch %v is newer than the latest head %v", epoch, BeaconLatestHeadEpoch)
	}
	if epoch == BeaconLatestHeadEpoch {
		// participation stats are calculated at the end of an epoch,
		// making it impossible to retrieve stats of an currently ongoing epoch
		return nil, fmt.Errorf("epoch %v can't be retrieved as it hasn't finished yet", epoch)
	}

	request_epoch := epoch
	startingSlot := request_epoch * utils.Config.Chain.SlotsPerEpoch
	endingSlot := startingSlot + utils.Config.Chain.SlotsPerEpoch
	totalVotes := uint64(0)
	totalEffectiveBalance := uint64(0)
	totalVotedBalance := uint64(0)
	totalValidators := uint64(0)
	totalParticipatingValidators := uint64(0)

	resp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/blocks/%d/attestations", beacon.endpoint, endingSlot))
	if err != nil {
		logger.Errorf("error retrieving attestations data for slot %v: %v", endingSlot, err)
		return nil, err
	}

	var parsedResp BlockAttestationResponse
	err = json.Unmarshal(resp, &parsedResp)
	if err != nil {
		logger.Errorf("error parsing attestations data for slot %v: %v", endingSlot, err)
		// continue
		return nil, err
	}

	for _, attestation := range parsedResp.Data {
		if attestation.AggregationBits == "" {
			continue
		}
		// Decode the attestation data
		decodedData, err := hexutil.Decode(attestation.AggregationBits)
		if err != nil {
			logger.Errorf("Error decoding attestation data: %v\n", err)
			continue
		}

		totalParticipatingValidators += countParticipation(decodedData)
		totalVotes += 1

	}

	votedBalance := validatorData[0].EffectiveBalance
	totalVotedBalance += totalVotes * (votedBalance)
	totalEffectiveBalance += validatorData[0].EffectiveBalance * uint64(len(validatorData))
	totalValidators += uint64(len(validatorData))

	res := &types.ValidatorParticipation{
		Epoch:                   epoch,
		GlobalParticipationRate: float32(totalParticipatingValidators) / float32(totalValidators),
		VotedEther:              totalVotedBalance,
		EligibleEther:           totalEffectiveBalance,
	}

	return res, nil
}

func (beacon *BeaconClient) GetValidatorMissedAttestationsCount(validators []*types.Validator, epoch uint64) (map[uint64]*types.ValidatorMissedAttestationsStatistic, error) {
	currentEpoch := epoch
	validatorMissedAttestationStats := make(map[uint64]*types.ValidatorMissedAttestationsStatistic)
	for _, validator := range validators {
		validatorMissedAttestationStats[validator.Index] = &types.ValidatorMissedAttestationsStatistic{
			Index:              validator.Index,
			MissedAttestations: 32,
			Epoch:              currentEpoch,
		}
	}
	// Iterate through the blocks of the current epoch
	for epochSlot := currentEpoch * 32; epochSlot < (currentEpoch+1)*32; epochSlot++ {
		// Fetch the block data
		resp, err := beacon.get(fmt.Sprintf("%s/eth/v1/beacon/blocks/%d/attestations", beacon.endpoint, epochSlot))
		if err != nil {
			logger.Errorf("error retrieving attestations data for slot %v: %v", epochSlot, err)

			for idx := range validatorMissedAttestationStats {
				if validatorMissedAttestationStats[idx].MissedAttestations > uint64(0) {
					validatorMissedAttestationStats[idx].MissedAttestations -= 1
				}
			}
			continue
		}

		var parsedResp BlockAttestationResponse
		err = json.Unmarshal(resp, &parsedResp)
		if err != nil {
			logger.Errorf("error parsing attestations data for slot %v: %v", epochSlot, err)
			for idx := range validatorMissedAttestationStats {
				if validatorMissedAttestationStats[idx].MissedAttestations > uint64(0) {
					validatorMissedAttestationStats[idx].MissedAttestations -= 1
				}
			}
			continue
		}

		// Iterate through the attestations in the block and count missed attestations
		for _, attestation := range parsedResp.Data {
			idx, err := strconv.ParseUint(attestation.Data.Index, 10, 32)
			if err != nil {
				continue
			}
			if validatorMissedAttestationStats[idx].MissedAttestations > uint64(0) {
				validatorMissedAttestationStats[idx].MissedAttestations -= 1
			}
		}
	}

	return validatorMissedAttestationStats, nil
}

// countParticipation counts the number of validators participated in the given attestation data
func countParticipation(data []byte) uint64 {
	voteCount := uint64(0)
	for _, vote := range data {
		voteCount += uint64(vote)
	}
	return voteCount
}

type uint64Str uint64

func (s *uint64Str) UnmarshalJSON(b []byte) error {
	return Uint64Unmarshal((*uint64)(s), b)
}

// Parse a uint64, with or without quotes, in any base, with common prefixes accepted to change base.
func Uint64Unmarshal(v *uint64, b []byte) error {
	if v == nil {
		return errors.New("nil dest in uint64 decoding")
	}
	if len(b) == 0 {
		return errors.New("empty uint64 input")
	}
	if b[0] == '"' || b[0] == '\'' {
		if len(b) == 1 || b[len(b)-1] != b[0] {
			return errors.New("uneven/missing quotes")
		}
		b = b[1 : len(b)-1]
	}
	n, err := strconv.ParseUint(string(b), 0, 64)
	if err != nil {
		return err
	}
	*v = n
	return nil
}

type bytesHexStr []byte

func (s *bytesHexStr) UnmarshalText(b []byte) error {
	if s == nil {
		return fmt.Errorf("cannot unmarshal bytes into nil")
	}
	if len(b) >= 2 && b[0] == '0' && b[1] == 'x' {
		b = b[2:]
	}
	out := make([]byte, len(b)/2)
	hex.Decode(out, b)
	*s = out
	return nil
}

var errNotFound = errors.New("not found 404")

func (beacon *BeaconClient) get(url string) ([]byte, error) {
	// t0 := time.Now()
	// defer func() { fmt.Println(url, time.Since(t0)) }()
	client := &http.Client{Timeout: time.Second * 1500}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, errNotFound
		}
		return nil, fmt.Errorf("url: %v, error-response: %s", url, data)
	}

	return data, err
}

func uint64List(li []uint64Str) []uint64 {
	out := make([]uint64, len(li))
	for i, v := range li {
		out[i] = uint64(v)
	}
	return out
}

type StandardValidatorEntry struct {
	Index     uint64Str `json:"index,string"`
	Balance   uint64Str `json:"balance,string"`
	Status    string    `json:"status"`
	Validator struct {
		Pubkey                     string    `json:"pubkey"`
		WithdrawalCredentials      string    `json:"withdrawal_credentials"`
		EffectiveBalance           uint64Str `json:"effective_balance,string"`
		Slashed                    bool      `json:"slashed"`
		ActivationEligibilityEpoch uint64Str `json:"activation_eligibility_epoch,string"`
		ActivationEpoch            uint64Str `json:"activation_epoch,string"`
		ExitEpoch                  uint64Str `json:"exit_epoch,string"`
		WithdrawableEpoch          uint64Str `json:"withdrawable_epoch,string"`
	} `json:"validator"`
}

type BlockAttestationResponse struct {
	ExecutionOptimistic bool `json:"execution_optimistic"`
	Finalized           bool `json:"finalized"`
	Data                []struct {
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
	} `json:"data"`
}

type StateValidatorsResponse struct {
	ExecutionOptimistic bool `json:"execution_optimistic"`
	Finalized           bool `json:"finalized"`
	Data                []struct {
		Index     string `json:"index"`
		Balance   string `json:"balance"`
		Status    string `json:"status"`
		Validator struct {
			Pubkey                     string `json:"pubkey"`
			WithdrawalCredentials      string `json:"withdrawal_credentials"`
			EffectiveBalance           string `json:"effective_balance"`
			Slashed                    bool   `json:"slashed"`
			ActivationEligibilityEpoch string `json:"activation_eligibility_epoch"`
			ActivationEpoch            string `json:"activation_epoch"`
			ExitEpoch                  string `json:"exit_epoch"`
			WithdrawableEpoch          string `json:"withdrawable_epoch"`
		} `json:"validator"`
	}
}

type StandardValidatorsResponse struct {
	Data []StandardValidatorEntry `json:"data"`
}

type StandardBeaconHeaderResponse struct {
	Data struct {
		Root      string `json:"root"`
		Canonical bool   `json:"canonical"`
		Header    struct {
			Message struct {
				Slot          uint64Str `json:"slot,string"`
				ProposerIndex uint64Str `json:"proposer_index,string"`
				ParentRoot    string    `json:"parent_root"`
				StateRoot     string    `json:"state_root"`
				BodyRoot      string    `json:"body_root"`
			} `json:"message"`
			Signature string `json:"signature"`
		} `json:"header"`
	} `json:"data"`
}

type StandardBeaconHeadersResponse struct {
	Data []struct {
		Root      string `json:"root"`
		Canonical bool   `json:"canonical"`
		Header    struct {
			Message struct {
				Slot          uint64Str `json:"slot,string"`
				ProposerIndex uint64Str `json:"proposer_index,string"`
				ParentRoot    string    `json:"parent_root"`
				StateRoot     string    `json:"state_root"`
				BodyRoot      string    `json:"body_root"`
			} `json:"message"`
			Signature string `json:"signature"`
		} `json:"header"`
	} `json:"data"`
}

type StandardFinalityCheckpointsResponse struct {
	Data struct {
		PreviousJustified struct {
			Epoch uint64Str `json:"epoch,string"`
			Root  string    `json:"root"`
		} `json:"previous_justified"`
		CurrentJustified struct {
			Epoch uint64Str `json:"epoch,string"`
			Root  string    `json:"root"`
		} `json:"current_justified"`
		Finalized struct {
			Epoch uint64Str `json:"epoch,string"`
			Root  string    `json:"root"`
		} `json:"finalized"`
	} `json:"data"`
}

type ProposerSlashing struct {
	SignedHeader1 struct {
		Message struct {
			Slot          uint64Str `json:"slot,string"`
			ProposerIndex uint64Str `json:"proposer_index,string"`
			ParentRoot    string    `json:"parent_root"`
			StateRoot     string    `json:"state_root"`
			BodyRoot      string    `json:"body_root"`
		} `json:"message"`
		Signature string `json:"signature"`
	} `json:"signed_header_1"`
	SignedHeader2 struct {
		Message struct {
			Slot          uint64Str `json:"slot,string"`
			ProposerIndex uint64Str `json:"proposer_index,string"`
			ParentRoot    string    `json:"parent_root"`
			StateRoot     string    `json:"state_root"`
			BodyRoot      string    `json:"body_root"`
		} `json:"message"`
		Signature string `json:"signature"`
	} `json:"signed_header_2"`
}

type AttesterSlashing struct {
	Attestation1 struct {
		AttestingIndices []uint64Str `json:"attesting_indices"`
		Signature        string      `json:"signature"`
		Data             struct {
			Slot            uint64Str `json:"slot,string"`
			Index           uint64Str `json:"index,string"`
			BeaconBlockRoot string    `json:"beacon_block_root"`
			Source          struct {
				Epoch uint64Str `json:"epoch,string"`
				Root  string    `json:"root"`
			} `json:"source"`
			Target struct {
				Epoch uint64Str `json:"epoch,string"`
				Root  string    `json:"root"`
			} `json:"target"`
		} `json:"data"`
	} `json:"attestation_1"`
	Attestation2 struct {
		AttestingIndices []uint64Str `json:"attesting_indices"`
		Signature        string      `json:"signature"`
		Data             struct {
			Slot            uint64Str `json:"slot,string"`
			Index           uint64Str `json:"index,string"`
			BeaconBlockRoot string    `json:"beacon_block_root"`
			Source          struct {
				Epoch uint64Str `json:"epoch,string"`
				Root  string    `json:"root"`
			} `json:"source"`
			Target struct {
				Epoch uint64Str `json:"epoch,string"`
				Root  string    `json:"root"`
			} `json:"target"`
		} `json:"data"`
	} `json:"attestation_2"`
}

type Attestation struct {
	AggregationBits string `json:"aggregation_bits"`
	Signature       string `json:"signature"`
	Data            struct {
		Slot            uint64Str `json:"slot,string"`
		Index           uint64Str `json:"index,string"`
		BeaconBlockRoot string    `json:"beacon_block_root"`
		Source          struct {
			Epoch uint64Str `json:"epoch,string"`
			Root  string    `json:"root"`
		} `json:"source"`
		Target struct {
			Epoch uint64Str `json:"epoch,string"`
			Root  string    `json:"root"`
		} `json:"target"`
	} `json:"data"`
}

type Deposit struct {
	Proof []string `json:"proof"`
	Data  struct {
		Pubkey                string    `json:"pubkey"`
		WithdrawalCredentials string    `json:"withdrawal_credentials"`
		Amount                uint64Str `json:"amount,string"`
		Signature             string    `json:"signature"`
	} `json:"data"`
}

type VoluntaryExit struct {
	Message struct {
		Epoch          uint64Str `json:"epoch,string"`
		ValidatorIndex uint64Str `json:"validator_index,string"`
	} `json:"message"`
	Signature string `json:"signature"`
}

type Eth1Data struct {
	DepositRoot  string    `json:"deposit_root"`
	DepositCount uint64Str `json:"deposit_count,string"`
	BlockHash    string    `json:"block_hash"`
}

type SyncAggregate struct {
	SyncCommitteeBits      string `json:"sync_committee_bits"`
	SyncCommitteeSignature string `json:"sync_committee_signature"`
}

type ExecutionPayload struct {
	ParentHash    bytesHexStr   `json:"parent_hash"`
	FeeRecipient  bytesHexStr   `json:"fee_recipient"`
	StateRoot     bytesHexStr   `json:"state_root"`
	ReceiptsRoot  bytesHexStr   `json:"receipts_root"`
	LogsBloom     bytesHexStr   `json:"logs_bloom"`
	PrevRandao    bytesHexStr   `json:"prev_randao"`
	BlockNumber   uint64Str     `json:"block_number"`
	GasLimit      uint64Str     `json:"gas_limit"`
	GasUsed       uint64Str     `json:"gas_used"`
	Timestamp     uint64Str     `json:"timestamp"`
	ExtraData     bytesHexStr   `json:"extra_data"`
	BaseFeePerGas uint64Str     `json:"base_fee_per_gas"`
	BlockHash     bytesHexStr   `json:"block_hash"`
	Transactions  []bytesHexStr `json:"transactions"`
	// present only after capella
	Withdrawals []WithdrawalPayload `json:"withdrawals"`
}

type WithdrawalPayload struct {
	Index          uint64Str   `json:"index,string"`
	ValidatorIndex uint64Str   `json:"validator_index"`
	Address        bytesHexStr `json:"address"`
	Amount         uint64Str   `json:"amount,string"`
}

type SignedBLSToExecutionChange struct {
	Message struct {
		ValidatorIndex     uint64Str   `json:"validator_index,string"`
		FromBlsPubkey      bytesHexStr `json:"from_bls_pubkey"`
		ToExecutionAddress bytesHexStr `json:"to_execution_address"`
	} `json:"message"`
	Signature bytesHexStr `json:"signature"`
}

type StandardCommitteeEntry struct {
	Index      uint64Str `json:"index,string"`
	Slot       uint64Str `json:"slot,string"`
	Validators []string  `json:"validators"`
}

type StandardCommitteesResponse struct {
	Data []StandardCommitteeEntry `json:"data"`
}

type AnySignedBlock struct {
	Message struct {
		Slot          uint64Str `json:"slot,string"`
		ProposerIndex uint64Str `json:"proposer_index,string"`
		ParentRoot    string    `json:"parent_root"`
		StateRoot     string    `json:"state_root"`
		Body          struct {
			RandaoReveal      string             `json:"randao_reveal"`
			Eth1Data          Eth1Data           `json:"eth1_data"`
			Graffiti          string             `json:"graffiti"`
			ProposerSlashings []ProposerSlashing `json:"proposer_slashings"`
			AttesterSlashings []AttesterSlashing `json:"attester_slashings"`
			Attestations      []Attestation      `json:"attestations"`
			Deposits          []Deposit          `json:"deposits"`
			VoluntaryExits    []VoluntaryExit    `json:"voluntary_exits"`

			// not present in phase0 blocks
			SyncAggregate *SyncAggregate `json:"sync_aggregate,omitempty"`

			// not present in phase0/altair blocks
			ExecutionPayload *ExecutionPayload `json:"execution_payload"`

			// present only after capella
			SignedBLSToExecutionChange []*SignedBLSToExecutionChange `json:"bls_to_execution_changes"`
		} `json:"body"`
	} `json:"message"`
	Signature bytesHexStr `json:"signature"`
}

type StandardSyncCommittee struct {
	Validators          []string   `json:"validators"`
	ValidatorAggregates [][]string `json:"validator_aggregates"`
}

type StandardSyncCommitteesResponse struct {
	Data StandardSyncCommittee `json:"data"`
}

type StandardV2BlockResponse struct {
	Version string         `json:"version"`
	Data    AnySignedBlock `json:"data"`
}

type StandardProposerDuty struct {
	Pubkey         string    `json:"pubkey"`
	ValidatorIndex uint64Str `json:"validator_index,string"`
	Slot           uint64Str `json:"slot,string"`
}

type StandardProposerDutiesResponse struct {
	DependentRoot string                 `json:"dependent_root"`
	Data          []StandardProposerDuty `json:"data"`
}
