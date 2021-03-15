package tools

import (
	"sync"
)

type LockMap struct {
	mapLock sync.Mutex
	mapData map[interface{}]*mapEntry
}

type mapEntry struct {
	belongsToMap *LockMap
	elLock       sync.Mutex
	refCount     int
	key          interface{}
}

// New returns an initalized LockMap
func NewLockMap() *LockMap {
	return &LockMap{mapData: make(map[interface{}]*mapEntry)}
}

// Unlocker is a wrapper of the original Unlock method allowing us to release the lock
type Unlocker interface {
	Unlock()
}

// Lock acquires a lock corresponding to this key and returns the element with the lock
func (lockMap *LockMap) Lock(key interface{}) Unlocker {

	lockMap.mapLock.Lock()

	element, ok := lockMap.mapData[key]
	if !ok {
		element = &mapEntry{belongsToMap: lockMap, key: key}
		lockMap.mapData[key] = element
	}
	element.refCount++

	lockMap.mapLock.Unlock()

	element.elLock.Lock()

	return element
}

// Unlock releases the lock for this element and deletes the element if it is not referenced by any other process
func (element *mapEntry) Unlock() {

	lockMap := element.belongsToMap

	lockMap.mapLock.Lock()

	element, ok := lockMap.mapData[element.key]
	if !ok {
		// Entry does not exist
		lockMap.mapLock.Unlock()
		return
	}

	element.refCount--
	if element.refCount < 1 {
		delete(lockMap.mapData, element.key)
	}
	lockMap.mapLock.Unlock()

	element.elLock.Unlock()
}
