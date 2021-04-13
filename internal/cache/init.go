package cache

import (
	"fmt"
	"log"
	"os"
)

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
