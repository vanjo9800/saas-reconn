package zonewalk

import (
	"fmt"
	"log"
	"saasreconn/internal/tools"
)

// AttemptWalk tests whether a particular zone supports DNSSEC and attempts zone-walking it
func AttemptWalk(config Config) (names []string, isDNSSEC bool) {
	// Mode 0 is just diagnosing nameservers
	// Mode 1 is NSEC zone-walking / NSEC3 zone-mapping + hash reversing
	// Mode 2 is just NSEC zone-walking / NSEC3 zone-mapping
	// Mode 3 is just NSEC zone-walking / NSEC3 hash reversing

	if len(config.Nameservers) == 0 {
		config.Nameservers = tools.GetNameservers(config.Zone)
	}

	if len(config.Nameservers) == 0 {
		log.Printf("No nameservers found for %s", config.Zone)
		return
	}

	dnssecType, salt, iterations := DetectDNSSECType(config, config.Nameservers[0])

	// Does not support DNSSEC
	if len(dnssecType) == 0 {
		return
	}

	if dnssecType == "nsec" {
		isDNSSEC = true
		if config.Mode == 0 {
			fmt.Printf("[%s] Detected an NSEC signed zone\n", config.Zone)
			return
		}
		log.Printf("[%s] Starting NSEC zone-walking...", config.Zone)
		names = append(names, NsecZoneWalking(config)...)
	} else if dnssecType == "nsec3" {
		isDNSSEC = true
		if config.Mode == 0 {
			fmt.Printf("[%s] Detected an NSEC3 signed zone - salt `%s` with  %d iterations\n", config.Zone, salt, iterations)
			return
		}
		if config.Mode != 3 {
			log.Printf("[%s] Starting NSEC3 zone-enumeration (salt `%s` and %d iterations)", config.Zone, salt, iterations)
			Nsec3ZoneEnumeration(config, salt, iterations)
		}
		if config.Mode != 2 {
			log.Printf("[%s] Starting NSEC3 hash reversing (salt `%s` and %d iterations)", config.Zone, salt, iterations)
			reversedNames, _ := Nsec3ZoneReversing(config, salt, iterations)
			names = append(names, reversedNames...)
		}
	} else {
		log.Printf("[%s] Unexpected DNSSEC record %s", config.Zone, dnssecType)
	}

	return names, isDNSSEC
}
