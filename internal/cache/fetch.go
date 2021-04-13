package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"saasreconn/internal/tools"
)

// FetchCachedDomainCheckResults fetches a cached result for a domain name from the cache database
func (cache *Cache) FetchCachedDomainCheckResults(domainName string, domainBase string) (cachedDomain *CachedDomainCheck, err error) {
	cachedData, err := cache.fetchCacheForDomainBase(domainBase)
	if err == nil {
		if cachedValue, ok := cachedData[domainName]; ok {
			return &cachedValue, nil
		}
	}

	return nil, errors.New("No previous cached data")
}

func (cache *Cache) fetchCacheForDomainBase(domainBase string) (data map[string]CachedDomainCheck, err error) {
	byteData, err := cache.fetchFromCache("checks", domainBase)
	if err != nil {
		// log.Printf("[%s] Could not find existing cache data", domainBase)
		return map[string]CachedDomainCheck{}, nil
	}

	err = json.Unmarshal(byteData, &data)
	if err != nil {
		log.Printf("Invalid cache data %s", err)
		return nil, err
	}

	return data, nil
}

// FetchCachedZoneWalk fetches a zonewalk specified by zone, salt and iterations, or returns an empty object
func (cache *Cache) FetchCachedZoneWalk(zone string, salt string, iterations int) (data CachedZoneWalk, err error) {
	zoneWalksForZone, err := cache.FetchZoneWalkForZone(zone)
	if err == nil {
		if cachedValue, ok := zoneWalksForZone[fmt.Sprintf("%s:%d", salt, iterations)]; ok {
			return cachedValue, nil
		}
		for _, zoneWalk := range zoneWalksForZone {
			if zoneWalk.Salt == salt && zoneWalk.Iterations == iterations {
				return zoneWalk, nil
			}
		}
	}

	return CachedZoneWalk{}, errors.New("No previous cache")
}

func (cache *Cache) FetchZoneWalkForZone(zone string) (data map[string]CachedZoneWalk, err error) {
	byteData, err := cache.fetchFromCache("zonewalk", zone)
	if err != nil {
		// log.Printf("[%s] Could not find existing cache data", zone)
		return map[string]CachedZoneWalk{}, nil
	}

	err = json.Unmarshal(byteData, &data)
	if err != nil {
		log.Printf("Invalid cache data %s", err)
		return nil, err
	}

	return data, nil
}

func (cache *Cache) fetchFromCache(path string, filename string) (data []byte, err error) {
	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()

	success := cache.initialise(path)
	if !success {
		log.Printf("Could not initialise cache")
		return nil, errors.New("Could not initialise cache")
	}

	byteData, err := ioutil.ReadFile(fmt.Sprintf("%s/%s/%s.json", cache.root, path, tools.NameToPath(filename)))
	if err != nil {
		// log.Printf("[%s/%s] Could not find existing cache data %s", path, filename, err)
		return []byte("{}"), nil
	}

	return byteData, nil
}
