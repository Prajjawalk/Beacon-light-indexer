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

### API definitions 
- The API specifications are listed in the Swagger doc which can be viewed in the form of UI once the server starts at path - http://<host>:<port>/api/v1/docs/index.html
  
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

- cache - This folder stores all the utility functions for initializing local indexer cache data and operating on it.
- cmd - The entry file for the indexer and functions for database schema migrations
- db - Functions related to database operations and saving epoch data are in this directory. The database used for this indexer is PostgreSQL because of its relational design which makes it a lot easier to store a combination of structured data and unstructured data in binary raw format.
- docs - Directory containing swagger documentation
- exporter - Directory containing functions to export and save epoch data, block data, validator missed attestation data to database
- rpc - Functions to interact with beacon RPC client are listed in this folder
- services - This directory contains schedulers that periodically updates the latest block and epoch data in the indexer cache
- types - Directory containing type definitions of various structures used throughout the code
- utils - Directory for utility functions
