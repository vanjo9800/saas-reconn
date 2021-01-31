package dns

import (
	"encoding/base32"
	"log"
	"math/big"
	"sort"
)

// rbt "github.com/emirpasic/gods/trees/redblacktree"

// ZoneRecord is the object entity in the linked list zone map
type ZoneRecord struct {
	name string
	prev string
	next string
}

// ZoneList is the instance of a LinkedList representing the zone map
// It also has some helper parameters such as number of links, number of records and expected size
type ZoneList struct {
	records      int64
	links        int
	expectedSize big.Int
	names        map[string]ZoneRecord
	noPrevious   map[string]bool
	noNext       map[string]bool
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
	return result.Quo(new(big.Float).SetInt(big.NewInt(list.records)), new(big.Float).SetInt(&list.expectedSize)).String()
}

// CreateZoneList constructs an empty zone list object
func CreateZoneList() *ZoneList {
	return &ZoneList{
		records:      0,
		links:        0,
		expectedSize: *sha1MaxSize,
		names:        map[string]ZoneRecord{},
		noPrevious:   map[string]bool{},
		noNext:       map[string]bool{},
	}
}

// AddRecord adds an NSEC3 record consisting of two consecutive hashes to the zone map
func (list *ZoneList) AddRecord(previous string, next string) {
	if record, exists := list.names[previous]; exists {
		if record.next == next {
			return
		}
		if record.next != "" {
			log.Printf("Inconsistent record found for %s: stored next %s, reported next %s", record.name, record.next, next)
			return
		}
		record.next = next
		list.names[previous] = record
		delete(list.noNext, previous)
	} else {
		record := ZoneRecord{
			name: previous,
			prev: "",
			next: next,
		}
		list.names[previous] = record
		list.records++
		list.noPrevious[previous] = true
	}

	if record, exists := list.names[next]; exists {
		if record.prev == previous {
			return
		}
		if record.prev != "" {
			log.Printf("Inconsistent record found for %s: stored previous %s, reported previous %s", record.name, record.prev, previous)
			return
		}
		record.prev = previous
		list.names[next] = record
		delete(list.noPrevious, next)
	} else {
		record := ZoneRecord{
			name: next,
			prev: previous,
			next: "",
		}
		list.names[next] = record
		list.records++
		list.noNext[next] = true
	}

	list.links++
	list.expectedSize.Sub(&list.expectedSize, coveredDistance(previous, next))
	// fmt.Printf("\rAdded %s followed by %s, coverage %s, hashes %d", previous, next, list.Coverage(), list.records)
}

// HashedNames returns the hashed names of the mapped records in a zone
func (list ZoneList) HashedNames() (result []string) {
	result = make([]string, 0, len(list.names))
	for key := range list.names {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
