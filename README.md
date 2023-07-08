# Beacon-light-indexer

This is the light indexer for the beacon chain which indexes the following - the latest 5 epochs, corresponding blocks for every epoch, execution data, validator participation rate, and global participation rate.

### Requirements

* [Go 1.18+](https://golang.org/dl/)

### Getting Started

- Clone the repository - `git clone https://github.com/Prajjawalk/Beacon-light-indexer.git`
- Copy the `config.example.yaml` file and make changes according to your environment.
- Perform database schema migrations using `go run cmd/migrations/postgres.go`

### Testing
```
$ go test -v ./...
```
### Building
```
$ go build cmd/indexer/main.go 
```

### Starting indexer
```
$ ./main --config {path_to_config}
```

### Code schema and directory structure
```
.
├── cache
│   └── cache.go
├── cmd
│   ├── indexer
│   │   ├── main.go
│   │   └── main_test.go
│   └── migrations
│       └── postgres.go
├── config.yaml
├── db
│   ├── db.go
│   └── migrations
│       └── 20230701133941_init_db.sql
├── docs
│   ├── docs.go
│   ├── swagger.json
│   └── swagger.yaml
├── exporter
│   └── exporter.go
├── go.mod
├── go.sum
├── handlers
│   ├── api.go
│   └── api_test.go
├── main
├── rpc
│   └── beacon.go
├── services
│   └── services.go
├── types
│   ├── api.go
│   ├── config.go
│   └── exporter.go
└── utils
    └── utils.go
```
