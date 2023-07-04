package utils

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Prajjawalk/beacon-light-indexer/types"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var Config *types.Config

func readConfigFile(cfg *types.Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("error opening config file %v: %v", path, err)
	}

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(cfg)
	if err != nil {
		return fmt.Errorf("error decoding config file %v: %v", path, err)
	}

	return nil
}

// ReadConfig will process a configuration
func ReadConfig(cfg *types.Config, path string) error {
	err := readConfigFile(cfg, path)
	if err != nil {
		return err
	}

	if cfg.Chain.GenesisTimestamp == 0 {
		switch cfg.Chain.Name {
		case "mainnet":
			cfg.Chain.GenesisTimestamp = 1606824023
		case "prater":
			cfg.Chain.GenesisTimestamp = 1616508000
		case "sepolia":
			cfg.Chain.GenesisTimestamp = 1655733600
		case "zhejiang":
			cfg.Chain.GenesisTimestamp = 1675263600
		case "gnosis":
			cfg.Chain.GenesisTimestamp = 1638993340
		default:
			return fmt.Errorf("tried to set known genesis-timestamp, but unknown chain-name")
		}
	}

	if cfg.Chain.GenesisValidatorsRoot == "" {
		switch cfg.Chain.Name {
		case "mainnet":
			cfg.Chain.GenesisValidatorsRoot = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
		case "prater":
			cfg.Chain.GenesisValidatorsRoot = "0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb"
		case "sepolia":
			cfg.Chain.GenesisValidatorsRoot = "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
		case "zhejiang":
			cfg.Chain.GenesisValidatorsRoot = "0x53a92d8f2bb1d85f62d16a156e6ebcd1bcaba652d0900b2c2f387826f3481f6f"
		case "gnosis":
			cfg.Chain.GenesisValidatorsRoot = "0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"
		default:
			return fmt.Errorf("tried to set known genesis-validators-root, but unknown chain-name")
		}
	}

	if cfg.Chain.DomainBLSToExecutionChange == "" {
		cfg.Chain.DomainBLSToExecutionChange = "0x0A000000"
	}
	if cfg.Chain.DomainVoluntaryExit == "" {
		cfg.Chain.DomainVoluntaryExit = "0x04000000"
	}

	logrus.WithFields(logrus.Fields{
		"genesisTimestamp":      cfg.Chain.GenesisTimestamp,
		"genesisValidatorsRoot": cfg.Chain.GenesisValidatorsRoot,
	}).Infof("did init config")

	return nil
}

// MustParseHex will parse a string into hex
func MustParseHex(hexString string) []byte {
	data, err := hex.DecodeString(strings.Replace(hexString, "0x", "", -1))
	if err != nil {
		log.Fatal(err)
	}
	return data
}

// SlotToTime returns a time.Time to slot
func SlotToTime(slot uint64) time.Time {
	return time.Unix(int64(Config.Chain.GenesisTimestamp+slot*Config.Chain.SecondsPerSlot), 0)
}

// TimeToEpoch will return an epoch for a given time
func TimeToEpoch(ts time.Time) int64 {
	if int64(Config.Chain.GenesisTimestamp) > ts.Unix() {
		return 0
	}
	return (ts.Unix() - int64(Config.Chain.GenesisTimestamp)) / int64(Config.Chain.SecondsPerSlot) / int64(Config.Chain.SlotsPerEpoch)
}

// TimeToSlot returns time to slot in seconds
func TimeToSlot(timestamp uint64) uint64 {
	if Config.Chain.GenesisTimestamp > timestamp {
		return 0
	}
	return (timestamp - Config.Chain.GenesisTimestamp) / Config.Chain.SecondsPerSlot
}

// EpochToTime will return a time.Time for an epoch
func EpochToTime(epoch uint64) time.Time {
	return time.Unix(int64(Config.Chain.GenesisTimestamp+epoch*Config.Chain.SecondsPerSlot*Config.Chain.SlotsPerEpoch), 0)
}

// WaitForCtrlC will block/wait until a control-c is pressed
func WaitForCtrlC() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

func GraffitiToSring(graffiti []byte) string {
	s := strings.Map(fixUtf, string(bytes.Trim(graffiti, "\x00")))
	s = strings.Replace(s, "\u0000", "", -1) // rempove 0x00 bytes as it is not supported in postgres

	if !utf8.ValidString(s) {
		return "INVALID_UTF8_STRING"
	}

	return s
}

func fixUtf(r rune) rune {
	if r == utf8.RuneError {
		return -1
	}
	return r
}

func BitAtVector(b []byte, i int) bool {
	bb := b[i/8]
	return (bb & (1 << uint(i%8))) > 0
}

// FormatAttestorAssignmentKey will format attestor assignment keys
func FormatAttestorAssignmentKey(AttesterSlot, CommitteeIndex, MemberIndex uint64) string {
	return fmt.Sprintf("%v-%v-%v", AttesterSlot, CommitteeIndex, MemberIndex)
}

func SqlRowsToJSON(rows *sql.Rows) ([]interface{}, error) {
	columnTypes, err := rows.ColumnTypes()

	if err != nil {
		return nil, fmt.Errorf("error getting column types: %w", err)
	}

	count := len(columnTypes)
	finalRows := []interface{}{}

	for rows.Next() {

		scanArgs := make([]interface{}, count)

		for i, v := range columnTypes {
			switch v.DatabaseTypeName() {
			case "VARCHAR", "TEXT", "UUID":
				scanArgs[i] = new(sql.NullString)
			case "BOOL":
				scanArgs[i] = new(sql.NullBool)
			case "INT4", "INT8":
				scanArgs[i] = new(sql.NullInt64)
			case "FLOAT8":
				scanArgs[i] = new(sql.NullFloat64)
			case "TIMESTAMP":
				scanArgs[i] = new(sql.NullTime)
			case "_INT4", "_INT8":
				scanArgs[i] = new(pq.Int64Array)
			default:
				scanArgs[i] = new(sql.NullString)
			}
		}

		err := rows.Scan(scanArgs...)

		if err != nil {
			return nil, fmt.Errorf("error scanning rows: %w", err)
		}

		masterData := map[string]interface{}{}

		for i, v := range columnTypes {

			//log.Println(v.Name(), v.DatabaseTypeName())
			if z, ok := (scanArgs[i]).(*sql.NullBool); ok {
				if z.Valid {
					masterData[v.Name()] = z.Bool
				} else {
					masterData[v.Name()] = nil
				}
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullString); ok {
				if z.Valid {
					if v.DatabaseTypeName() == "BYTEA" {
						if len(z.String) > 0 {
							masterData[v.Name()] = "0x" + hex.EncodeToString([]byte(z.String))
						} else {
							masterData[v.Name()] = nil
						}
					} else if v.DatabaseTypeName() == "NUMERIC" {
						nbr, _ := new(big.Int).SetString(z.String, 10)
						masterData[v.Name()] = nbr
					} else {
						masterData[v.Name()] = z.String
					}
				} else {
					masterData[v.Name()] = nil
				}
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullInt64); ok {
				if z.Valid {
					masterData[v.Name()] = z.Int64
				} else {
					masterData[v.Name()] = nil
				}
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullInt32); ok {
				if z.Valid {
					masterData[v.Name()] = z.Int32
				} else {
					masterData[v.Name()] = nil
				}
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullFloat64); ok {
				if z.Valid {
					masterData[v.Name()] = z.Float64
				} else {
					masterData[v.Name()] = nil
				}
				continue
			}

			if z, ok := (scanArgs[i]).(*sql.NullTime); ok {
				if z.Valid {
					masterData[v.Name()] = z.Time.Unix()
				} else {
					masterData[v.Name()] = nil
				}
				continue
			}

			masterData[v.Name()] = scanArgs[i]
		}

		finalRows = append(finalRows, masterData)
	}

	return finalRows, nil
}
