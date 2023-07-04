package cache

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/coocood/freecache"
	"github.com/sirupsen/logrus"
)

type indexerCache struct {
	localGoCache *freecache.Cache
}

var IndexerCache *indexerCache

func MustInitIndexerCache() {
	IndexerCache = &indexerCache{}
	IndexerCache.localGoCache = freecache.NewCache(100 * 1024 * 1024) // 100 MB
}

func (cache *indexerCache) SetString(key, value string, expiration time.Duration) error {
	return cache.localGoCache.Set([]byte(key), []byte(value), int(expiration.Seconds()))
}

func (cache *indexerCache) GetStringWithLocalTimeout(key string, localExpiration time.Duration) (string, error) {
	// try to retrieve the key from the local cache
	wanted, err := cache.localGoCache.Get([]byte(key))

	return string(wanted), err
}

func (cache *indexerCache) SetUint64(key string, value uint64, expiration time.Duration) error {

	return cache.localGoCache.Set([]byte(key), []byte(fmt.Sprintf("%d", value)), int(expiration.Seconds()))
}

func (cache *indexerCache) GetUint64WithLocalTimeout(key string, localExpiration time.Duration) (uint64, error) {

	// try to retrieve the key from the local cache
	wanted, err := cache.localGoCache.Get([]byte(key))
	if err == nil {
		returnValue, err := strconv.ParseUint(string(wanted), 10, 64)
		if err != nil {
			return 0, err
		}
		return returnValue, nil
	}

	return 0, err
}

func (cache *indexerCache) SetBool(key string, value bool, expiration time.Duration) error {
	return cache.localGoCache.Set([]byte(key), []byte(fmt.Sprintf("%t", value)), int(expiration.Seconds()))
}

func (cache *indexerCache) GetBoolWithLocalTimeout(key string, localExpiration time.Duration) (bool, error) {

	// try to retrieve the key from the local cache
	wanted, err := cache.localGoCache.Get([]byte(key))
	if err == nil {
		returnValue, err := strconv.ParseBool(string(wanted))
		if err != nil {
			return false, err
		}
		return returnValue, nil
	}

	return false, err
}

func (cache *indexerCache) GetWithLocalTimeout(key string, localExpiration time.Duration, returnValue interface{}) (interface{}, error) {
	// try to retrieve the key from the local cache
	wanted, err := cache.localGoCache.Get([]byte(key))
	if err == nil {
		err = json.Unmarshal([]byte(wanted), returnValue)
		if err != nil {
			logrus.Errorf("error (GetWithLocalTimeout) unmarshalling data for key %v: %v", key, err)
			return nil, err
		}
		return returnValue, nil
	}

	return nil, err
}
