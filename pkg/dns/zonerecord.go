package dns

import (
	"encoding/base32"
	"log"
	"math/big"
	"saasreconn/pkg/cache"
	"sync"

	rbt "github.com/emirpasic/gods/trees/redblacktree"
)

// ZoneRecord is the object entity in the linked list zone map
type ZoneRecord struct {
	Name string
	Prev string
	Next string
}

// ZoneList is the instance of a LinkedList representing the zone map
// It also has some helper parameters such as number of links, number of records and expected size
type ZoneList struct {
	ExpectedSize big.Int
	Names        *rbt.Tree
	addingMutex  sync.Mutex
}

var sha1MaxSize *big.Int = new(big.Int).Exp(big.NewInt(2), big.NewInt(160), big.NewInt(0))

func nsec3HashToNumber(hash string) *big.Int {
	sha1Data, err := base32.HexEncoding.DecodeString(hash)
	if err != nil {
		log.Printf("Could not parse base32 hash %s due to %s", hash, err)
		return nil
	}

	number := new(big.Int)
	number.SetBytes(sha1Data)
	return number
}

func coveredDistance(hash1 string, hash2 string) *big.Int {

	number1 := nsec3HashToNumber(hash1)
	number2 := nsec3HashToNumber(hash2)

	if number1.Cmp(number2) == -1 {
		// number1 < number 2
		// hashes are in order
		result := new(big.Int)
		return result.Sub(number2, number1)
	}
	// We reached the end of the zone, so we get the last and first entry
	result := new(big.Int)
	return number2.Add(result.Sub(sha1MaxSize, number1), number2)
}

// Coverage returns an estimated coverage of the zone based on the number of current entries and the maximum projected number of entries
func (list *ZoneList) Coverage() string {
	result := new(big.Float)
	return result.Quo(new(big.Float).SetInt(big.NewInt(list.records())), new(big.Float).SetInt(&list.ExpectedSize)).String()
}

// CreateZoneList constructs an empty zone list object
func CreateZoneList(cachedZoneList cache.CachedZoneList) *ZoneList {
	if len(cachedZoneList.Names) == 0 {
		return &ZoneList{
			ExpectedSize: *sha1MaxSize,
			Names:        rbt.NewWithStringComparator(),
		}
	}

	hashesTree := rbt.NewWithStringComparator()
	for index := range cachedZoneList.Names {
		hashesTree.Put(cachedZoneList.Names[index], ZoneRecord{
			Name: cachedZoneList.Names[index],
			Prev: cachedZoneList.Prev[index],
			Next: cachedZoneList.Next[index],
		})
	}
	expectedSize := new(big.Int)
	expectedSize.SetString(cachedZoneList.ExpectedSize, 10)

	return &ZoneList{
		ExpectedSize: *expectedSize,
		Names:        hashesTree,
	}
}

func (list *ZoneList) updateNextRecord(record ZoneRecord, newNext string) {
	list.addingMutex.Lock()
	log.Printf("Record update found for %s: old next %s, new next %s", record.Name, record.Next, newNext)
	if record.Next > newNext {
		log.Printf("A record has been added: %s", newNext)
	} else {
		log.Printf("A record has been removed: %s", newNext)
	}
	var toRemove []string
	current := record
	for current.Next != "" && current.Next < newNext {
		toRemove = append(toRemove, current.Next)
		currentData, _ := list.Names.Get(current.Next)
		current = currentData.(ZoneRecord)
	}
	lastRecordedNameInChain := current.Name
	if current.Next != "" {
		lastRecordedNameInChain = current.Next
		nextRecordData, _ := list.Names.Get(current.Next)
		nextRecord := nextRecordData.(ZoneRecord)
		nextRecord.Prev = ""
		list.Names.Put(nextRecord.Name, nextRecord)
	}
	list.ExpectedSize.Add(&list.ExpectedSize, coveredDistance(current.Name, lastRecordedNameInChain))
	for i := range toRemove {
		list.Names.Remove(toRemove[i])
	}
	list.addingMutex.Unlock()
}

func (list *ZoneList) updatePrevRecord(record ZoneRecord, newPrev string) {
	list.addingMutex.Lock()
	log.Printf("Record update found for %s: old previous %s, new previous %s", record.Name, record.Prev, newPrev)
	if record.Prev < newPrev {
		log.Printf("A record has been added: %s", newPrev)
	} else {
		log.Printf("A record has been removed: %s", newPrev)
	}
	var toRemove []string
	current := record
	for current.Prev != "" && current.Prev > newPrev {
		toRemove = append(toRemove, current.Prev)
		currentData, _ := list.Names.Get(current.Prev)
		current = currentData.(ZoneRecord)
	}
	lastRecordedNameInChain := current.Name
	if current.Prev != "" {
		lastRecordedNameInChain = current.Prev
		prevRecordData, _ := list.Names.Get(current.Prev)
		prevRecord := prevRecordData.(ZoneRecord)
		prevRecord.Next = ""
		list.Names.Put(prevRecord.Name, prevRecord)
	}
	list.ExpectedSize.Add(&list.ExpectedSize, coveredDistance(lastRecordedNameInChain, current.Name))
	for i := range toRemove {
		list.Names.Remove(toRemove[i])
	}
	list.addingMutex.Unlock()
}

// AddRecord adds an NSEC3 record consisting of two consecutive hashes to the zone map
func (list *ZoneList) AddRecord(previous string, next string) {
	var record ZoneRecord

	if recordInterface, exists := list.Names.Get(previous); exists {
		record = recordInterface.(ZoneRecord)
		if record.Next == next {
			return
		}
		if record.Next != "" {
			list.updateNextRecord(record, next)
		}
		record.Next = next
	} else {
		record = ZoneRecord{
			Name: previous,
			Prev: "",
			Next: next,
		}
	}
	list.addingMutex.Lock()
	list.Names.Put(previous, record)
	list.addingMutex.Unlock()

	if recordInterface, exists := list.Names.Get(next); exists {
		record = recordInterface.(ZoneRecord)
		if record.Prev == previous {
			return
		}
		if record.Prev != "" {
			list.updatePrevRecord(record, previous)
		}
		record.Prev = previous
	} else {
		record = ZoneRecord{
			Name: next,
			Prev: previous,
			Next: "",
		}
	}
	list.addingMutex.Lock()
	list.Names.Put(next, record)
	list.addingMutex.Unlock()

	list.addingMutex.Lock()
	list.ExpectedSize.Sub(&list.ExpectedSize, coveredDistance(previous, next))
	list.addingMutex.Unlock()
}

func (list *ZoneList) records() int64 {
	return int64(list.Names.Size())
}

// Closest returns the closest record found near a certain hash
func (list *ZoneList) Closest(hash string) ZoneRecord {
	node, _ := list.Names.Floor(hash)
	if node == nil {
		return ZoneRecord{
			Name: "",
			Prev: "",
			Next: "",
		}
	}
	return node.Value.(ZoneRecord)
}

// HashedNames returns the hashed names of the mapped records in a zone
func (list *ZoneList) HashedNames() (result []string) {
	result = []string{}
	for _, hash := range list.Names.Keys() {
		result = append(result, hash.(string))
	}

	return result
}

// ExportList exports a constructed ZoneList
func (list *ZoneList) ExportList() (exportList cache.CachedZoneList) {
	exportList = cache.CachedZoneList{
		Names:        []string{},
		Prev:         []string{},
		Next:         []string{},
		ExpectedSize: list.ExpectedSize.String(),
	}

	for _, node := range list.Names.Values() {
		exportList.Names = append(exportList.Names, node.(ZoneRecord).Name)
		exportList.Prev = append(exportList.Prev, node.(ZoneRecord).Prev)
		exportList.Next = append(exportList.Next, node.(ZoneRecord).Next)
	}

	return exportList
}
