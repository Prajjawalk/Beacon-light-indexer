-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS 
    validator_missed_attestations (
        validatorindex INT NOT NULL,
        latest_epoch INT NOT NULL,
        missedattestations INT NOT NULL,
        PRIMARY KEY (validatorindex)
    );

CREATE TABLE IF NOT EXISTS
    epochs (
        epoch INT NOT NULL,
        blockscount INT NOT NULL DEFAULT 0,
        proposerslashingscount INT NOT NULL,
        attesterslashingscount INT NOT NULL,
        attestationscount INT NOT NULL,
        depositscount INT NOT NULL,
        withdrawalcount INT NOT NULL DEFAULT 0,
        voluntaryexitscount INT NOT NULL,
        validatorscount INT NOT NULL,
        averagevalidatorbalance BIGINT NOT NULL,
        totalvalidatorbalance BIGINT NOT NULL,
        finalized bool,
        eligibleether BIGINT,
        globalparticipationrate FLOAT,
        votedether BIGINT,
        rewards_exported bool NOT NULL DEFAULT FALSE,
        PRIMARY KEY (epoch)
    );

CREATE TABLE IF NOT EXISTS
    blocks (
        epoch INT NOT NULL,
        slot INT NOT NULL,
        blockroot bytea NOT NULL,
        parentroot bytea NOT NULL,
        stateroot bytea NOT NULL,
        signature bytea NOT NULL,
        randaoreveal bytea,
        graffiti bytea,
        graffiti_text TEXT NULL,
        eth1data_depositroot bytea,
        eth1data_depositcount INT NOT NULL,
        eth1data_blockhash bytea,
        syncaggregate_bits bytea,
        syncaggregate_signature bytea,
        syncaggregate_participation FLOAT NOT NULL DEFAULT 0,
        proposerslashingscount INT NOT NULL,
        attesterslashingscount INT NOT NULL,
        attestationscount INT NOT NULL,
        depositscount INT NOT NULL,
        withdrawalcount INT NOT NULL DEFAULT 0,
        voluntaryexitscount INT NOT NULL,
        proposer INT NOT NULL,
        status TEXT NOT NULL,
        /* Can be 0 = scheduled, 1 proposed, 2 missed, 3 orphaned */
        -- https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
        -- https://github.com/ethereum/consensus-specs/blob/v1.1.9/specs/bellatrix/beacon-chain.md#executionpayload
        exec_parent_hash bytea,
        exec_fee_recipient bytea,
        exec_state_root bytea,
        exec_receipts_root bytea,
        exec_logs_bloom bytea,
        exec_random bytea,
        exec_block_number INT,
        exec_gas_limit INT,
        exec_gas_used INT,
        exec_timestamp INT,
        exec_extra_data bytea,
        exec_base_fee_per_gas BIGINT,
        exec_block_hash bytea,
        exec_transactions_count INT NOT NULL DEFAULT 0,
        PRIMARY KEY (slot, blockroot)
    );

CREATE INDEX IF NOT EXISTS idx_blocks_proposer ON blocks (proposer);

CREATE INDEX IF NOT EXISTS idx_blocks_epoch ON blocks (epoch);

CREATE INDEX IF NOT EXISTS idx_blocks_graffiti_text ON blocks USING gin (graffiti_text gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_blocks_blockrootstatus ON blocks (blockroot, status);

CREATE INDEX IF NOT EXISTS idx_blocks_exec_block_number ON blocks (exec_block_number);

CREATE TABLE IF NOT EXISTS
    blocks_withdrawals (
        block_slot INT NOT NULL,
        block_root bytea NOT NULL,
        withdrawalindex INT NOT NULL,
        validatorindex INT NOT NULL,
        address bytea NOT NULL,
        amount BIGINT NOT NULL,
        -- in GWei
        PRIMARY KEY (block_slot, block_root, withdrawalindex)
    );

CREATE INDEX IF NOT EXISTS idx_blocks_withdrawals_recipient ON blocks_withdrawals (address);

CREATE INDEX IF NOT EXISTS idx_blocks_withdrawals_validatorindex ON blocks_withdrawals (validatorindex);

CREATE TABLE IF NOT EXISTS
    blocks_bls_change (
        block_slot INT NOT NULL,
        block_root bytea NOT NULL,
        validatorindex INT NOT NULL,
        signature bytea NOT NULL,
        pubkey bytea NOT NULL,
        address bytea NOT NULL,
        PRIMARY KEY (block_slot, block_root, validatorindex)
    );

CREATE INDEX IF NOT EXISTS idx_blocks_bls_change_pubkey ON blocks_bls_change (pubkey);

CREATE INDEX IF NOT EXISTS idx_blocks_bls_change_address ON blocks_bls_change (address);

CREATE TABLE IF NOT EXISTS
    blocks_transactions (
        block_slot INT NOT NULL,
        block_index INT NOT NULL,
        block_root bytea NOT NULL DEFAULT '',
        raw bytea NOT NULL,
        txhash bytea NOT NULL,
        nonce INT NOT NULL,
        gas_price bytea NOT NULL,
        gas_limit BIGINT NOT NULL,
        sender bytea NOT NULL,
        recipient bytea NOT NULL,
        amount bytea NOT NULL,
        payload bytea NOT NULL,
        max_priority_fee_per_gas BIGINT,
        max_fee_per_gas BIGINT,
        PRIMARY KEY (block_slot, block_index)
    );

CREATE TABLE IF NOT EXISTS
    blocks_proposerslashings (
        block_slot INT NOT NULL,
        block_index INT NOT NULL,
        block_root bytea NOT NULL DEFAULT '',
        proposerindex INT NOT NULL,
        header1_slot BIGINT NOT NULL,
        header1_parentroot bytea NOT NULL,
        header1_stateroot bytea NOT NULL,
        header1_bodyroot bytea NOT NULL,
        header1_signature bytea NOT NULL,
        header2_slot BIGINT NOT NULL,
        header2_parentroot bytea NOT NULL,
        header2_stateroot bytea NOT NULL,
        header2_bodyroot bytea NOT NULL,
        header2_signature bytea NOT NULL,
        PRIMARY KEY (block_slot, block_index)
    );

CREATE TABLE IF NOT EXISTS
    blocks_attesterslashings (
        block_slot INT NOT NULL,
        block_index INT NOT NULL,
        block_root bytea NOT NULL DEFAULT '',
        attestation1_indices INTEGER[] NOT NULL,
        attestation1_signature bytea NOT NULL,
        attestation1_slot BIGINT NOT NULL,
        attestation1_index INT NOT NULL,
        attestation1_beaconblockroot bytea NOT NULL,
        attestation1_source_epoch INT NOT NULL,
        attestation1_source_root bytea NOT NULL,
        attestation1_target_epoch INT NOT NULL,
        attestation1_target_root bytea NOT NULL,
        attestation2_indices INTEGER[] NOT NULL,
        attestation2_signature bytea NOT NULL,
        attestation2_slot BIGINT NOT NULL,
        attestation2_index INT NOT NULL,
        attestation2_beaconblockroot bytea NOT NULL,
        attestation2_source_epoch INT NOT NULL,
        attestation2_source_root bytea NOT NULL,
        attestation2_target_epoch INT NOT NULL,
        attestation2_target_root bytea NOT NULL,
        PRIMARY KEY (block_slot, block_index)
    );

CREATE TABLE IF NOT EXISTS
    blocks_attestations (
        block_slot INT NOT NULL,
        block_index INT NOT NULL,
        block_root bytea NOT NULL DEFAULT '',
        aggregationbits bytea NOT NULL,
        validators INT[] NOT NULL,
        signature bytea NOT NULL,
        slot INT NOT NULL,
        committeeindex INT NOT NULL,
        beaconblockroot bytea NOT NULL,
        source_epoch INT NOT NULL,
        source_root bytea NOT NULL,
        target_epoch INT NOT NULL,
        target_root bytea NOT NULL,
        PRIMARY KEY (block_slot, block_index)
    );

CREATE INDEX IF NOT EXISTS idx_blocks_attestations_beaconblockroot ON blocks_attestations (beaconblockroot);

CREATE INDEX IF NOT EXISTS idx_blocks_attestations_source_root ON blocks_attestations (source_root);

CREATE INDEX IF NOT EXISTS idx_blocks_attestations_target_root ON blocks_attestations (target_root);

CREATE TABLE IF NOT EXISTS
    blocks_deposits (
        block_slot INT NOT NULL,
        block_index INT NOT NULL,
        block_root bytea NOT NULL DEFAULT '',
        proof bytea[],
        publickey bytea NOT NULL,
        withdrawalcredentials bytea NOT NULL,
        amount BIGINT NOT NULL,
        signature bytea NOT NULL,
        valid_signature bool NOT NULL DEFAULT TRUE,
        PRIMARY KEY (block_slot, block_index)
    );

CREATE INDEX IF NOT EXISTS idx_blocks_deposits_publickey ON blocks_deposits (publickey);

CREATE TABLE IF NOT EXISTS
    blocks_voluntaryexits (
        block_slot INT NOT NULL,
        block_index INT NOT NULL,
        block_root bytea NOT NULL DEFAULT '',
        epoch INT NOT NULL,
        validatorindex INT NOT NULL,
        signature bytea NOT NULL,
        PRIMARY KEY (block_slot, block_index)
    );

CREATE TABLE IF NOT EXISTS
    network_liveness (
        ts TIMESTAMP WITHOUT TIME ZONE,
        headepoch INT NOT NULL,
        finalizedepoch INT NOT NULL,
        justifiedepoch INT NOT NULL,
        previousjustifiedepoch INT NOT NULL,
        PRIMARY KEY (ts)
    );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'NOT SUPPORTED';
-- +goose StatementEnd
