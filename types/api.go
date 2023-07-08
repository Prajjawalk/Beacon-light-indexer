package types

type ApiResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}

type APIEpochResponse struct {
	Epoch                   uint64 `json:"epoch"`
	Ts                      uint64 `json:"ts"`
	AttestationsCount       uint64 `json:"attestationscount"`
	AttesterSlashingsCount  uint64 `json:"attesterslashingscount"`
	AverageValidatorBalance uint64 `json:"averagevalidatorbalance"`
	BlocksCount             uint64 `json:"blockscount"`
	DepositsCount           uint64 `json:"depositscount"`
	EligibleEther           uint64 `json:"eligibleether"`
	Finalized               bool   `json:"finalized"`
	GlobalParticipationRate uint64 `json:"globalparticipationrate"`
	MissedBlocks            uint64 `json:"missedblocks"`
	OrphanedBlocks          uint64 `json:"orphanedblocks"`
	ProposedBlocks          uint64 `json:"proposedblocks"`
	ProposerSlashingsCount  uint64 `json:"proposerslashingscount"`
	ScheduledBlocks         uint64 `json:"scheduledblocks"`
	TotalValidatorBalance   uint64 `json:"totalvalidatorbalance"`
	ValidatorsCount         uint64 `json:"validatorscount"`
	VoluntaryExitsCount     uint64 `json:"voluntaryexitscount"`
	VotedEther              uint64 `json:"votedether"`
	RewardsExported         uint64 `json:"rewards_exported"`
	WithdrawalCount         uint64 `json:"withdrawalcount"`
}

type APISlotResponse struct {
	Attestationscount          uint64  `json:"attestationscount"`
	Attesterslashingscount     uint64  `json:"attesterslashingscount"`
	Blockroot                  string  `json:"blockroot"`
	Depositscount              uint64  `json:"depositscount"`
	Epoch                      uint64  `json:"epoch"`
	Eth1dataBlockhash          string  `json:"eth1data_blockhash"`
	Eth1dataDepositcount       uint64  `json:"eth1data_depositcount"`
	Eth1dataDepositroot        string  `json:"eth1data_depositroot"`
	ExecBaseFeePerGas          uint64  `json:"exec_base_fee_per_gas" extensions:"x-nullable"`
	ExecBlockHash              string  `json:"exec_block_hash" extensions:"x-nullable"`
	ExecBlockNumber            uint64  `json:"exec_block_number" extensions:"x-nullable"`
	ExecExtraData              string  `json:"exec_extra_data" extensions:"x-nullable"`
	ExecFeeRecipient           string  `json:"exec_fee_recipient" extensions:"x-nullable"`
	ExecGasLimit               uint64  `json:"exec_gas_limit" extensions:"x-nullable"`
	ExecGasUsed                uint64  `json:"exec_gas_used" extensions:"x-nullable"`
	ExecLogsBloom              string  `json:"exec_logs_bloom" extensions:"x-nullable"`
	ExecParentHash             string  `json:"exec_parent_hash" extensions:"x-nullable"`
	ExecRandom                 string  `json:"exec_random" extensions:"x-nullable"`
	ExecReceiptsRoot           string  `json:"exec_receipts_root" extensions:"x-nullable"`
	ExecStateRoot              string  `json:"exec_state_root" extensions:"x-nullable"`
	ExecTimestamp              uint64  `json:"exec_timestamp" extensions:"x-nullable"`
	ExecTransactionsCount      uint64  `json:"exec_transactions_count" extensions:"x-nullable"`
	Graffiti                   string  `json:"graffiti"`
	GraffitiText               string  `json:"graffiti_text"`
	Parentroot                 string  `json:"parentroot"`
	Proposer                   uint64  `json:"proposer"`
	Proposerslashingscount     uint64  `json:"proposerslashingscount"`
	Randaoreveal               string  `json:"randaoreveal"`
	Signature                  string  `json:"signature"`
	Slot                       uint64  `json:"slot"`
	Stateroot                  string  `json:"stateroot"`
	Status                     string  `json:"status"`
	SyncaggregateBits          string  `json:"syncaggregate_bits"`
	SyncaggregateParticipation float64 `json:"syncaggregate_participation"`
	SyncaggregateSignature     string  `json:"syncaggregate_signature"`
	Voluntaryexitscount        uint64  `json:"voluntaryexitscount"`
	WithdrawalCount            uint64  `json:"withdrawalcount"`
}

type GlobalParticipationRateResp struct {
	ParticipationRate float32
}

type ValidatorParticipationrateResp struct {
	ParticipationRate float32
	Index             uint64
}
