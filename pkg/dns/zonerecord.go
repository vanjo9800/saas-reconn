package dns

import (
	"encoding/base32"
	"log"
	"math/big"

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
	links        int
	expectedSize big.Int
	names        *rbt.Tree
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
	return result.Quo(new(big.Float).SetInt(big.NewInt(list.records())), new(big.Float).SetInt(&list.expectedSize)).String()
}

// CreateZoneList constructs an empty zone list object
func CreateZoneList() *ZoneList {
	return &ZoneList{
		expectedSize: *sha1MaxSize,
		names:        rbt.NewWithStringComparator(),
		noPrevious:   map[string]bool{},
		noNext:       map[string]bool{},
	}
}

// AddRecord adds an NSEC3 record consisting of two consecutive hashes to the zone map
func (list *ZoneList) AddRecord(previous string, next string) {
	if record, exists := list.names.Get(previous); exists {
		record := record.(ZoneRecord)
		if record.Next == next {
			return
		}
		if record.Next != "" {
			log.Printf("Inconsistent record found for %s: stored next %s, reported next %s", record.Name, record.Next, next)
			return
		}
		record.Next = next
		list.names.Put(previous, record)
		delete(list.noNext, previous)
	} else {
		record := ZoneRecord{
			Name: previous,
			Prev: "",
			Next: next,
		}
		list.names.Put(previous, record)
		list.noPrevious[previous] = true
	}

	if record, exists := list.names.Get(next); exists {
		record := record.(ZoneRecord)
		if record.Prev == previous {
			return
		}
		if record.Prev != "" {
			log.Printf("Inconsistent record found for %s: stored previous %s, reported previous %s", record.Name, record.Prev, previous)
			return
		}
		record.Prev = previous
		list.names.Put(next, record)
		delete(list.noPrevious, next)
	} else {
		record := ZoneRecord{
			Name: next,
			Prev: previous,
			Next: "",
		}
		list.names.Put(next, record)
		list.noNext[next] = true
	}

	list.links++
	list.expectedSize.Sub(&list.expectedSize, coveredDistance(previous, next))
	// fmt.Printf("\rAdded %s followed by %s, coverage %s, hashes %d", previous, next, list.Coverage(), list.records)
}

func (list *ZoneList) records() int64 {
	return int64(list.names.Size())
}

// Closest returns the closest record found near a certain hash
func (list ZoneList) Closest(hash string) ZoneRecord {
	node, _ := list.names.Floor(hash)
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
func (list ZoneList) HashedNames() (result []string) {
	result = []string{}
	for _, hash := range list.names.Keys() {
		result = append(result, hash.(string))
	}

	return result
}
