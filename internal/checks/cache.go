package checks

import (
	"encoding/json"
	"errors"
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

type CachedDomain struct {
	Address  []string
	PageBody bool
	Updated  time.Time
}

// NewCache constructs a new empty caching directory
func NewCache() *Cache {
	return &Cache{
		initialised: false,
	}
}

// nameToPath is a method which escapes a name, so we can use it as a filename
func nameToPath(filename string) string {
	// Escape symbols
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, " ", " ")
	escapedName = strings.ReplaceAll(escapedName, "\\", "_")
	escapedName = strings.ReplaceAll(escapedName, "/", " ")

	return escapedName
}

// Initialise the database main folder
func (cache *Cache) Initialise() bool {

	if !cache.initialised {
		if _, err := os.Stat("cache/"); os.IsNotExist(err) {
			err := os.Mkdir("cache/", 0755)
			if err != nil {
				log.Fatal(err)
				return false
			}
		}
		cache.initialised = true
	}

	return cache.initialised
}

func (cache *Cache) FetchCachedResults(domainName string, domainBase string) (cachedDomain *CachedDomain, err error) {
	cachedData, err := cache.fetchAllCachedResults(domainBase)
	if err != nil {
		return nil, errors.New("No previous cached data")
	}

	if cachedValue, ok := cachedData[domainName]; ok {
		return &cachedValue, nil
	}

	return nil, errors.New("No previous cached data")
}

func (cache *Cache) fetchAllCachedResults(domainBase string) (data map[string]CachedDomain, err error) {
	success := cache.Initialise()
	if !success {
		log.Fatal("Could not initialise cache")
		return nil, errors.New("Could not initialise cache")
	}

	byteData, err := ioutil.ReadFile("cache/" + nameToPath(domainBase) + ".json")
	if err != nil {
		log.Printf("[%s] Could not find existing cache data", domainBase)
		return map[string]CachedDomain{}, nil
	}

	err = json.Unmarshal(byteData, &data)
	if err != nil {
		log.Fatal("Invalid cache data")
		return nil, err
	}

	return data, nil
}

func (cache *Cache) saveCacheData(data map[string]CachedDomain, domainBase string) error {
	success := cache.Initialise()
	if !success {
		log.Fatalf("[%s] Could not initialise cache", domainBase)
	}

	jsonOutput, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("[%s] Could not convert to JSON", domainBase)
	}

	err = ioutil.WriteFile("cache/"+nameToPath(domainBase)+".json", jsonOutput, 0755)
	if err != nil {
		log.Fatalf("[%s] Failed to write cached data", domainBase)
	}

	return nil
}

func (cache *Cache) UpdateCache(domainName string, domainBase string, cachedSubdomain CachedDomain) {
	cachedData, err := cache.fetchAllCachedResults(domainBase)
	if err != nil {
		log.Fatalf("[%s] There was an error fetching cached data", domainBase)
	}

	cachedData[domainName] = cachedSubdomain

	err = cache.saveCacheData(cachedData, domainBase)
	if err != nil {
		log.Fatalf("[%s] Could not update cached data", domainBase)
	}
}

// DeleteProvider deletes provider data
func (cache *Cache) DeleteCache(domainBase string) bool {
	success := cache.Initialise()
	if !success {
		log.Fatal("Could not initialise cache")
		return false
	}

	// Check if provider data exists and delete only if there
	if _, err := os.Stat("cache/"); os.IsExist(err) {
		err := os.Remove("cache/" + nameToPath(domainBase) + ".json")
		if err != nil {
			log.Fatal("Could not detele data file")
			return false
		}
		return true
	}

	return true
}
