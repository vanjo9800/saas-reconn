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
	for count, domain := range diff.added {
		if count == 10 {
			log.Printf("\t... and %d more\n", len(diff.added)-count)
			break
		}
		log.Printf("\t+ %s, conf. %d", domain.Name, domain.Confidence)
	}
}
