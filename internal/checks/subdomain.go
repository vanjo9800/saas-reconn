package checks

import "log"

type SubdomainRange struct {
	Base     string
	Prefixes []string
}

func (data SubdomainRange) Dump() {
	if len(data.Prefixes) == 0 {
		return
	}

	log.Printf("Subdomains of %s", data.Base)
	for _, prefix := range data.Prefixes {
		log.Printf("  - %s.%s", prefix, data.Base)
	}
}
