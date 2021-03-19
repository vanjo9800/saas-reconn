package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"saasreconn/pkg/tools"
	"sync"
	"time"
)

var cacheRWLock sync.Mutex

// Cache is our intermediate data storage class
type Cache struct {
	initialised bool
	root        string
}

// CachedDomainCheck is an instance of a subdomain check in our caching system
type CachedDomainCheck struct {
	Address  []string
	PageBody bool
	Updated  time.Time
}

// CachedZoneList is an instance of a cached ZoneList
type CachedZoneList struct {
	Names []string
	Prev  []string
	Next  []string
}

// CachedZoneWalk is an instance of a zonewalk in our caching system
type CachedZoneWalk struct {
	Salt       string
	Iterations int
	Hashes     []string
	List       CachedZoneList
	Guessed    map[string]string
	Updated    time.Time
}

/* INITIALISATION */

// NewCache constructs a new empty caching directory
func NewCache() *Cache {
	return &Cache{
		initialised: false,
		root:        "data/cache/",
	}
}

// Initialise the database main folder
func (cache *Cache) Initialise(path string) bool {
	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()

	if !cache.initialised {
		if _, err := os.Stat(fmt.Sprintf("%s/%s/", cache.root, path)); os.IsNotExist(err) {
			err := os.MkdirAll(fmt.Sprintf("%s/%s/", cache.root, path), 0755)
			if err != nil {
				log.Printf("An error occurred when initialising cache for %s: %s", path, err)
				return false
			}
		}
		cache.initialised = true
	}

	return cache.initialised
}

/* FETCHING */

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
		log.Printf("[%s] Could not find existing cache data", domainBase)
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
		log.Printf("[%s] Could not find existing cache data", zone)
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
	success := cache.Initialise(path)
	if !success {
		log.Printf("Could not initialise cache")
		return nil, errors.New("Could not initialise cache")
	}

	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()
	byteData, err := ioutil.ReadFile(fmt.Sprintf("%s/%s/%s.json", cache.root, path, tools.NameToPath(filename)))
	if err != nil {
		log.Printf("[%s/%s] Could not find existing cache data %s", path, filename, err)
		return []byte("{}"), nil
	}

	return byteData, nil
}

/* WRITING */

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

	zoneWalksForZone[fmt.Sprintf("%s:%d", zoneWalkData.Salt, zoneWalkData.Iterations)] = zoneWalkData

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
	success := cache.Initialise(path)
	if !success {
		return errors.New("Could not initialise cache")
	}

	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()
	err := ioutil.WriteFile(fmt.Sprintf("%s/%s/%s.json", cache.root, path, tools.NameToPath(filename)), data, 0755)
	if err != nil {
		return errors.New("Failed to write back to cache")
	}

	return nil
}

/* DELETING */

// DeleteDomainCheckCache deletes a cache file from domain checking
func (cache *Cache) DeleteDomainCheckCache(domainBase string) bool {
	return cache.deleteFile("checks", domainBase)
}

// DeleteZoneWalkCache deletes a cache file from zone-walking
func (cache *Cache) DeleteZoneWalkCache(domainBase string) bool {
	return cache.deleteFile("zonewalk", domainBase)
}

func (cache *Cache) deleteFile(path string, filename string) bool {
	success := cache.Initialise(path)
	if !success {
		log.Fatal("Could not initialise cache")
		return false
	}

	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()
	// Check if cached data exists and delete only if there
	if _, err := os.Stat(fmt.Sprintf("%s/%s/", cache.root, path)); os.IsExist(err) {
		err := os.Remove(fmt.Sprintf("%s/%s/%s.json", cache.root, path, tools.NameToPath(filename)))
		if err != nil {
			log.Fatal("Could not detele data file")
			return false
		}
		return true
	}

	return true
}
