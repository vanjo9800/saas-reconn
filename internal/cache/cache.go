package cache

import (
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
