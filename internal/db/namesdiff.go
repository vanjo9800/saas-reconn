package db

import (
	"log"
)

type DataDiff struct {
	added []string
	removed []string
}

func (diff *DataDiff) dump() {
	log.Println("Added:");
	for _, domain := range diff.added {
		log.Println("\t+ " + domain);
	}
	log.Println("Removed:");
	for _, domain := range diff.removed {
		log.Println("\t- " + domain );
	}
}
