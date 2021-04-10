package zonewalk

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
	DistanceSum big.Int
	Distances   *rbt.Tree
	Names       *rbt.Tree
	addingMutex sync.Mutex
}

func BigIntComparator(a, b interface{}) int {
	aBigInt := a.(*big.Int)
	bBigInt := b.(*big.Int)
	return aBigInt.Cmp(bBigInt)
}

var sha1MaxSize *big.Int = new(big.Int).Exp(big.NewInt(2), big.NewInt(160), big.NewInt(0))

func nsec3HashToNumber(hash string) *big.Int {
	sha1Data, err := base32.HexEncoding.DecodeString(hash)
	if err != nil {
		log.Printf("Unexpected error: Could not parse base32 hash %s due to %s", hash, err)
		return nil
	}

	number := new(big.Int)
	number.SetBytes(sha1Data)
	return number
}

func CoveredDistance(hash1 string, hash2 string) *big.Int {

	number1 := nsec3HashToNumber(hash1)
	number2 := nsec3HashToNumber(hash2)

	if number1 == nil || number2 == nil {
		log.Printf("There is something wrong with NSEC3 record: %s -> %s, returning 0", hash1, hash2)
		return big.NewInt(0)
	}

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

func (list *ZoneList) addDistanceMetric(distance *big.Int) {
	// Add to overall distance sum
	list.DistanceSum.Add(&list.DistanceSum, distance)

	// Add to distances tree
	val, ok := list.Distances.Get(distance)
	if !ok {
		list.Distances.Put(distance, 1)
	} else {
		list.Distances.Put(distance, val.(int)+1)
	}
}

func (list *ZoneList) removeDistanceMetric(distance *big.Int) {
	// Remove from overall distance sum
	list.DistanceSum.Sub(&list.DistanceSum, distance)

	// Remove from distance tree
	val, ok := list.Distances.Get(distance)
	if !ok {
		log.Printf("Unexpected error: Error distance %s not found in tree", distance)
	} else {
		if val.(int) == 1 {
			list.Distances.Remove(distance)
		} else {
			list.Distances.Put(distance, val.(int)-1)
		}
	}
}

const quantiles = 10

var quantileWeights = []float64{0.41, 0.15, 0.10, 0.08, 0.07, 0.05, 0.05, 0.04, 0.03, 0.02}

// Coverage returns an estimated coverage of the zone based on the number of current entries and the maximum projected number of entries
func (list *ZoneList) Coverage() (string, string) {

	list.addingMutex.Lock()
	defer func() {
		list.addingMutex.Unlock()
	}()

	if list.Distances.Size() == 0 {
		return "0", "0"
	}
	// Unquantiled
	result1 := new(big.Float)
	result1.Quo(new(big.Float).SetInt(&list.DistanceSum), big.NewFloat(float64(list.Distances.Size())))
	result1.Quo(new(big.Float).SetInt(sha1MaxSize), result1)

	// Quantiled
	result2 := big.NewFloat(0.0)
	perQuantile := list.Distances.Size() / quantiles
	remainder := list.Distances.Size() % quantiles
	distanceIterator := list.Distances.Iterator()
	distanceIterator.Begin()
	quantileSum := big.NewFloat(0.0)
	quantileIndex := 0
	count := 0
	for distanceIterator.Next() {
		currentDistanceFloat := new(big.Float).SetInt(distanceIterator.Key().(*big.Int))
		countOfDistance := distanceIterator.Value().(int)
		for distanceCount := 0; distanceCount < countOfDistance; distanceCount++ {
			if count >= perQuantile {
				if count == perQuantile && remainder > 0 {
					remainder--
				} else {
					if quantileIndex >= 10 {
						log.Printf("Something went wrong %d and %d", perQuantile, remainder)
					}
					quantileSum.Mul(quantileSum, big.NewFloat(quantileWeights[quantileIndex]))
					quantileSum.Quo(quantileSum, big.NewFloat(float64(count)))
					result2.Add(result2, quantileSum)
					quantileIndex++
					quantileSum = quantileSum.SetFloat64(0.0)
					count = 0
				}
			}
			quantileSum = quantileSum.Add(quantileSum, currentDistanceFloat)
			count++
		}
	}
	result2.Quo(new(big.Float).SetInt(sha1MaxSize), result2)

	return result1.String(), result2.String()
}

// CreateZoneList constructs an empty zone list object
func CreateZoneList(cachedZoneList cache.CachedZoneList) (list *ZoneList) {
	if len(cachedZoneList.Names) == 0 {
		list = &ZoneList{
			DistanceSum: *big.NewInt(0),
			Distances:   rbt.NewWith(BigIntComparator),
			Names:       rbt.NewWithStringComparator(),
		}
		return list
	}

	list = &ZoneList{
		DistanceSum: *big.NewInt(0),
		Distances:   rbt.NewWith(BigIntComparator),
		Names:       rbt.NewWithStringComparator(),
	}
	for index := range cachedZoneList.Names {
		list.Names.Put(cachedZoneList.Names[index], ZoneRecord{
			Name: cachedZoneList.Names[index],
			Prev: cachedZoneList.Prev[index],
			Next: cachedZoneList.Next[index],
		})
		if cachedZoneList.Next[index] != "" {
			list.addDistanceMetric(CoveredDistance(cachedZoneList.Names[index], cachedZoneList.Next[index]))
		}
	}

	return list
}

func (list *ZoneList) updateNextRecord(record ZoneRecord, newNext string) {
	list.addingMutex.Lock()
	// log.Printf("Record update found for %s: old next %s, new next %s", record.Name, record.Next, newNext)
	// if record.Next > newNext {
	// 	log.Printf("A record has been added: %s", newNext)
	// } else {
	// 	log.Printf("A record has been removed: %s", newNext)
	// }
	var toRemove []string

	// Remove all intermediate hashes (they are no longer valid!)
	current := record
	for current.Next != "" && current.Next < newNext {
		list.removeDistanceMetric(CoveredDistance(current.Name, current.Next))
		toRemove = append(toRemove, current.Next)
		currentData, _ := list.Names.Get(current.Next)
		current = currentData.(ZoneRecord)
	}

	// Break connection with last removed hash
	if current.Next != "" {
		list.removeDistanceMetric(CoveredDistance(current.Name, current.Next))
		nextRecordData, _ := list.Names.Get(current.Next)
		nextRecord := nextRecordData.(ZoneRecord)
		nextRecord.Prev = ""
		list.Names.Put(nextRecord.Name, nextRecord)
	}

	// Actually remove hashes
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

	// Remove all intermediate hashes (they are no longer valid!)
	current := record
	for current.Prev != "" && current.Prev > newPrev {
		list.removeDistanceMetric(CoveredDistance(current.Prev, current.Name))
		toRemove = append(toRemove, current.Prev)
		currentData, _ := list.Names.Get(current.Prev)
		current = currentData.(ZoneRecord)
	}

	// Break connection with last removed hash
	if current.Prev != "" {
		list.removeDistanceMetric(CoveredDistance(current.Prev, current.Name))
		prevRecordData, _ := list.Names.Get(current.Prev)
		prevRecord := prevRecordData.(ZoneRecord)
		prevRecord.Next = ""
		list.Names.Put(prevRecord.Name, prevRecord)
	}

	// Actually remove hashes
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
	list.addDistanceMetric(CoveredDistance(previous, next))
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

// Covered returns whether a certain hash is covered by the zone information
func (list *ZoneList) Covered(hash string) bool {
	// Find its predecessor, or the node itself
	node := list.Closest(hash)
	if node.Name != "" && node.Next >= hash {
		return true
	}

	// If we know the boundary hashes of the zone, we can discard all others in between them
	if list.Names.Size() > 0 {
		node = list.Names.Left().Value.(ZoneRecord)
		if node.Prev != "" {
			return true
		}
	}

	return false
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
		Names: []string{},
		Prev:  []string{},
		Next:  []string{},
	}

	for _, node := range list.Names.Values() {
		exportList.Names = append(exportList.Names, node.(ZoneRecord).Name)
		exportList.Prev = append(exportList.Prev, node.(ZoneRecord).Prev)
		exportList.Next = append(exportList.Next, node.(ZoneRecord).Next)
	}

	return exportList
}
