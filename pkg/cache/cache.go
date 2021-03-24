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

func MergeCachedZoneLists(list1 CachedZoneList, list2 CachedZoneList) (result CachedZoneList) {
	// list1 and list2 must be sorted
	result = CachedZoneList{
		Names: []string{},
		Prev:  []string{},
		Next:  []string{},
	}

	index1, index2 := 0, 0
	for index1 < len(list1.Names) && index2 < len(list2.Names) {
		if list1.Names[index1] == list2.Names[index2] {
			result.Names = append(result.Names, list1.Names[index1])
			result.Prev = append(result.Prev, list1.Prev[index1])
			result.Next = append(result.Next, list1.Next[index1])
			index1++
			index2++
		} else if list1.Names[index1] < list2.Names[index2] {
			result.Names = append(result.Names, list1.Names[index1])
			result.Prev = append(result.Prev, list1.Prev[index1])
			result.Next = append(result.Next, list1.Next[index1])
			index1++
		} else {
			result.Names = append(result.Names, list2.Names[index2])
			result.Prev = append(result.Prev, list2.Prev[index2])
			result.Next = append(result.Next, list2.Next[index2])
			index2++
		}
	}

	for index1 < len(list1.Names) {
		result.Names = append(result.Names, list1.Names[index1])
		result.Prev = append(result.Prev, list1.Prev[index1])
		result.Next = append(result.Next, list1.Next[index1])
		index1++
	}
	for index2 < len(list2.Names) {
		result.Names = append(result.Names, list2.Names[index2])
		result.Prev = append(result.Prev, list2.Prev[index2])
		result.Next = append(result.Next, list2.Next[index2])
		index2++
	}

	return result
}

/* INITIALISATION */

// NewCache constructs a new empty caching directory
func NewCache() *Cache {
	return &Cache{
		initialised: false,
		root:        "data/cache/",
	}
}

func (cache *Cache) initialise(path string) bool {
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
	cacheRWLock.Lock()
	defer cacheRWLock.Unlock()

	success := cache.initialise(path)
	if !success {
		log.Fatal("Could not initialise cache")
		return false
	}

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
