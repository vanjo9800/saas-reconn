package db

import (
	"log"
)

// DataDiff is a class for reporting difference in provider data during updates
type DataDiff struct {
	added   []string
	removed []string
}

// Dump is a helper method which prints the whole difference comparison of the data
func (diff *DataDiff) Dump() {
	log.Println("Added:")
	for _, domain := range diff.added {
		log.Println("\t+ " + domain)
	}
	// log.Println("Removed:")
	// for _, domain := range diff.removed {
	// 	log.Println("\t- " + domain)
	// }
}
