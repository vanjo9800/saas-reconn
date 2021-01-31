package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

// Cache is our intermediate data storage class
type Cache struct {
	initialised bool
}

type CachedDomainCheck struct {
	Address  []string
	PageBody bool
	Updated  time.Time
}

type CachedZoneWalk struct {
	Salt       string
	Iterations int
	Hashes     []string
	Guessed    map[string]string
	Updated    time.Time
}

/* HELPER FUNCTIONS */

// nameToPath is a method which escapes a name, so we can use it as a filename
func nameToPath(filename string) string {
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, "/|\\| ", "_")

	return escapedName
}

/* INITIALISATION */

// NewCache constructs a new empty caching directory
func NewCache() *Cache {
	return &Cache{
		initialised: false,
	}
}

// Initialise the database main folder
func (cache *Cache) Initialise(path string) bool {

	if !cache.initialised {
		if _, err := os.Stat(fmt.Sprintf("cache/%s/", path)); os.IsNotExist(err) {
			err := os.MkdirAll(fmt.Sprintf("cache/%s/", path), 0755)
			if err != nil {
				log.Fatal(err)
				return false
			}
		}
		cache.initialised = true
	}

	return cache.initialised
}

/* FETCHING */

func (cache *Cache) FetchCachedDomainCheckResults(domainName string, domainBase string) (cachedDomain *CachedDomainCheck, err error) {
	cachedData, err := cache.fetchCacheForDomainBase(domainBase)
	if err != nil {
		return nil, errors.New("No previous cached data")
	}

	if cachedValue, ok := cachedData[domainName]; ok {
		return &cachedValue, nil
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
		log.Println("Invalid cache data")
		return nil, err
	}

	return data, nil
}

func (cache *Cache) FetchCachedZoneWalk(domainBase string) (data CachedZoneWalk, err error) {
	byteData, err := cache.fetchFromCache("zonewalk", domainBase)
	if err != nil {
		log.Printf("[%s] Could not find existing cache data %s", domainBase, err)
		return CachedZoneWalk{}, nil
	}

	err = json.Unmarshal(byteData, &data)
	if err != nil {
		log.Println("Invalid cache data")
		return CachedZoneWalk{}, err
	}

	return data, nil
}

func (cache *Cache) fetchFromCache(path string, filename string) (data []byte, err error) {
	success := cache.Initialise(path)
	if !success {
		log.Fatal("Could not initialise cache")
		return nil, errors.New("Could not initialise cache")
	}

	byteData, err := ioutil.ReadFile(fmt.Sprintf("cache/%s/%s.json", path, nameToPath(filename)))
	if err != nil {
		log.Printf("[%s/%s] Could not find existing cache data %s", path, filename, err)
		return []byte{}, nil
	}

	return byteData, nil
}

/* WRITING */

func (cache *Cache) UpdateCachedDomainCheckData(domainName string, domainBase string, cachedSubdomain CachedDomainCheck) {
	cachedData, err := cache.fetchCacheForDomainBase(domainBase)
	if err != nil {
		log.Fatalf("[%s] There was an error fetching cached data", domainBase)
	}

	cachedData[domainName] = cachedSubdomain

	jsonOutput, err := json.Marshal(cachedData)
	if err != nil {
		log.Fatalf("[%s] Could not convert to JSON", domainBase)
	}

	err = cache.saveCachedData("checks", domainBase, jsonOutput)
	if err != nil {
		log.Fatalf("[%s] Could not update cached data", domainBase)
	}
}

func (cache *Cache) UpdateCachedZoneWalkData(domainBase string, zoneWalkData CachedZoneWalk) {
	jsonOutput, err := json.Marshal(zoneWalkData)
	if err != nil {
		log.Fatalf("[%s] Could not convert to JSON", domainBase)
	}

	err = cache.saveCachedData("zonewalk", domainBase, jsonOutput)
	if err != nil {
		log.Fatalf("[%s] Could not update cached data", domainBase)
	}
}

func (cache *Cache) saveCachedData(path string, filename string, data []byte) error {
	success := cache.Initialise(path)
	if !success {
		log.Fatalf("[%s/%s] Could not initialise cache", path, filename)
	}

	err := ioutil.WriteFile(fmt.Sprintf("cache/%s/%s.json", path, nameToPath(filename)), data, 0755)
	if err != nil {
		log.Fatalf("[%s/%s] Failed to write cached data", path, filename)
	}

	return nil
}

/* DELETING */

func (cache *Cache) DeleteDomainCheckCache(domainBase string) bool {
	return cache.DeleteFile("checks", domainBase)
}

func (cache *Cache) DeleteZoneWalkCache(domainBase string) bool {
	return cache.DeleteFile("zonewalk", domainBase)
}

func (cache *Cache) DeleteFile(path string, filename string) bool {
	success := cache.Initialise(path)
	if !success {
		log.Fatal("Could not initialise cache")
		return false
	}

	// Check if cached data exists and delete only if there
	if _, err := os.Stat(fmt.Sprintf("cache/%s/", path)); os.IsExist(err) {
		err := os.Remove(fmt.Sprintf("cache/%s/%s.json", path, nameToPath(filename)))
		if err != nil {
			log.Fatal("Could not detele data file")
			return false
		}
		return true
	}

	return true
}
