package cache

import (
	"fmt"
	"log"
	"os"
	"saasreconn/internal/tools"
)

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
