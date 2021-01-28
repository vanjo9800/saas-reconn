package dns

import (
	"encoding/base32"
	"fmt"
	"log"
	"math/big"
)

// rbt "github.com/emirpasic/gods/trees/redblacktree"

type ZoneRecord struct {
	name string
	prev string
	next string
}

type ZoneList struct {
	records      int64
	links        int
	expectedSize big.Int
	names        map[string]ZoneRecord
	noPrevious   map[string]bool
	noNext       map[string]bool
}

var SHA1_MAX_SIZE *big.Int = new(big.Int).Exp(big.NewInt(2), big.NewInt(160), big.NewInt(0))

func nsec3HashToNumber(hash string) *big.Int {
	sha1_data, err := base32.HexEncoding.DecodeString(hash)
	if err != nil {
		log.Printf("Could not parse base32 hash %s due to %s", hash, err)
		return nil
	}

	number := new(big.Int)
	number.SetBytes(sha1_data)
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
	} else {
		// We reached the end of the zone, so we get the last and first entry
		result := new(big.Int)
		return number2.Add(result.Sub(SHA1_MAX_SIZE, number1), number2)
	}
}

func (list *ZoneList) Coverage() string {
	result := new(big.Float)
	return result.Quo(new(big.Float).SetInt(big.NewInt(list.records)), new(big.Float).SetInt(&list.expectedSize)).String()
}

func CreateZoneList() *ZoneList {
	return &ZoneList{
		records:      0,
		links:        0,
		expectedSize: *SHA1_MAX_SIZE,
		names:        map[string]ZoneRecord{},
		noPrevious:   map[string]bool{},
		noNext:       map[string]bool{},
	}
}

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
	fmt.Printf("\rAdded %s followed by %s, coverage %s, hashes %d", previous, next, list.Coverage(), list.records)
}

func (list ZoneList) Names() (result []string) {
	result = make([]string, 0, len(list.names))
	for key := range list.names {
		result = append(result, key)
	}
	return result
}
