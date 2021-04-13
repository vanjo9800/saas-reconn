package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"saasreconn/internal/tools"
)

func (cache *Cache) UpdateCachedDomainCheckData(domainName string, domainBase string, cachedSubdomain CachedDomainCheck) {
	cachedData, err := cache.fetchCacheForDomainBase(domainBase)
	if err != nil {
		log.Printf("[%s] There was an error fetching cached data", domainBase)
		return
	}

	cachedData[domainName] = cachedSubdomain

	jsonOutput, err := json.Marshal(cachedData)
	if err != nil {
		log.Printf("[%s] Could not convert to JSON", domainBase)
		return
	}

	err = cache.saveCachedData("checks", domainBase, jsonOutput)
	if err != nil {
		log.Printf("[%s] Could not update cached data", domainBase)
		return
	}
}

func (cache *Cache) UpdateCachedZoneWalkData(zone string, zoneWalkData CachedZoneWalk) {
	zoneWalksForZone, err := cache.FetchZoneWalkForZone(zone)
	if err != nil {
		log.Printf("[%s] There was an error fetching cached data", zone)
		return
	}

	current, ok := zoneWalksForZone[fmt.Sprintf("%s:%d", zoneWalkData.Salt, zoneWalkData.Iterations)]
	if !ok {
		current = CachedZoneWalk{
			Salt:       zoneWalkData.Salt,
			Iterations: zoneWalkData.Iterations,
			Hashes:     []string{},
			List: CachedZoneList{
				Names: []string{},
				Prev:  []string{},
				Next:  []string{},
			},
			Guessed: map[string]string{},
		}
	}
	current.Hashes = tools.UniqueStrings(append(current.Hashes, zoneWalkData.Hashes...))
	current.List = MergeCachedZoneLists(current.List, zoneWalkData.List)
	for hash, guess := range zoneWalkData.Guessed {
		current.Guessed[hash] = guess
	}
	zoneWalksForZone[fmt.Sprintf("%s:%d", zoneWalkData.Salt, zoneWalkData.Iterations)] = current

	jsonOutput, err := json.Marshal(zoneWalksForZone)
	if err != nil {
		log.Printf("[%s] Could not convert to JSON", zone)
		return
	}

	err = cache.saveCachedData("zonewalk", zone, jsonOutput)
	if err != nil {
		log.Printf("[%s] Could not update cached data", zone)
		return
	}
}

func (cache *Cache) saveCachedData(path string, filename string, data []byte) error {
	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()

	success := cache.initialise(path)
	if !success {
		return errors.New("Could not initialise cache")
	}

	err := ioutil.WriteFile(fmt.Sprintf("%s/%s/%s.json", cache.root, path, tools.NameToPath(filename)), data, 0755)
	if err != nil {
		return errors.New("Failed to write back to cache")
	}

	return nil
}
