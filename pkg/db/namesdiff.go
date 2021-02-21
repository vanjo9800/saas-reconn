package db

import (
	"log"
)

// DataDiff is a class for reporting difference in provider data during updates
type DataDiff struct {
	added []Subdomain
}

// Dump is a helper method which prints the whole difference comparison of the data
func (diff *DataDiff) Dump() {
	if len(diff.added) == 0 {
		return
	}

	log.Println("Added:")
	for _, domain := range diff.added {
		log.Printf("\t+ %s, conf. %d", domain.Name, domain.Confidence)
	}
}
