package types

type Config struct {
	IndexerDatabase struct {
		Username string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
	} `yaml:"indexerDatabase"`
	BeaconNodeUrl string `yaml:"beaconnodeUrl"`
	IndexBlocks   bool
	Chain         struct {
		Name                       string `yaml:"name"`
		GenesisTimestamp           uint64 `yaml:"genesisTimestamp"`
		GenesisValidatorsRoot      string `yaml:"genesisValidatorsRoot"`
		DomainBLSToExecutionChange string `yaml:"domainBLSToExecutionChange"`
		DomainVoluntaryExit        string `yaml:"domainVoluntaryExit"`
		SlotsPerEpoch              uint64 `yaml:"slotsPerEpoch"`
		SecondsPerSlot             uint64 `yaml:"secondsPerSlot"`
		DepositChainID             uint64 `yaml:"depositChainId"`
		AltairForkEpoch            uint64 `yaml:"altairForkEpoch"`
		SyncCommitteeSize          uint64 `yaml:"syncCommitteeSize"`
	} `yaml:"chain"`
	Server struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
}

type DatabaseConfig struct {
	Username string
	Password string
	Name     string
	Host     string
	Port     string
}
