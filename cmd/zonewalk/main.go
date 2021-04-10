package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"saasreconn/pkg/db"
	"saasreconn/pkg/provider"
	"saasreconn/pkg/zonewalk"
)

const zoneWalkConfidence = 70

func runZoneWalking(resultsDatabase *db.Database, name string, config zonewalk.Config, custom bool) {
	found, isDNSSEC := zonewalk.AttemptWalk(config)
	if isDNSSEC {
		log.Printf("[%s] Found %d names from DNSSEC zone-walking", config.Zone, len(found))
	} else if custom {
		log.Printf("[%s] No DNSSEC nameserver found", config.Zone)
		return
	}
	if custom {
		for count, name := range found {
			if count == 10 {
				fmt.Printf("\t and %d more\n", len(found)-10)
				break
			}
			fmt.Printf("\t + %s\n", name)
		}
	}
	diff, _ := resultsDatabase.UpdateProvider(name, config.Zone, db.MapStringNamesToSubdomain(found, zoneWalkConfidence, "Zone-walking"))
	diff.Dump()
}

func main() {

	// Read flags
	domain := flag.String("domain", "", "run zone-walking for a specific domain")
	endpointsConfig := flag.String("endpoints-config", "configs/saas-endpoints.yaml", "a SaaS providers endpoints file")
	hashcat := flag.Bool("hashcat", true, "use hashcat for reversing NSEC3 hashes")
	listProviders := flag.Bool("list-providers", false, "list all supported providers")
	nameserver := flag.String("nameserver", "", "run zone-walking for a specific nameserver")
	noCache := flag.Bool("no-cache", false, "a bool whether to use pre-existing")
	parallelRequests := flag.Int("parallel", 5, "number of DNS requests to send in parallel")
	providerName := flag.String("provider", "", "run zone-walking for a specific provider")
	rateLimit := flag.Int("rate-limit", 20, "limit the number of DNS requests per second to avoid blocking (0 for minimal limit for contention protection, -1 for no limit at all)")
	timeout := flag.Int("timeout", 60, "number of seconds to run a zone zonewalk mapping")
	updateCache := flag.Bool("update-cache", true, "should the command update the current zone-walking cache entries")
	verbose := flag.Int("verbose", 3, "verbosity factor")
	walkmode := flag.Int("mode", 1, " what mode to use for zone-walking (0 for just DNSSEC test, 1 for both mapping and reversing, 2 for just mapping and storing cache, and 3 for just reversing based on cache)")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}
	fmt.Println("Executing zone-walking script")

	config := zonewalk.Config{
		Nameserver:   *nameserver,
		Timeout:      *timeout,
		MappingCache: !*noCache,
		GuessesCache: !*noCache,
		UpdateCache:  *updateCache,
		Mode:         *walkmode,
		Parallel:     *parallelRequests,
		RateLimit:    *rateLimit,
		Hashcat:      *hashcat,
		Verbose:      *verbose,
	}

	if *domain != "" {
		config.Zone = *domain
		runZoneWalking(resultsDatabase, *domain, config, true)
		os.Exit(0)
	}

	for name, data := range saasProviders {
		if *listProviders {
			fmt.Println(name)
			continue
		}
		if *providerName != "" && *providerName != name {
			continue
		}
		for _, domain := range data.Subdomain {
			config.Zone = domain
			runZoneWalking(resultsDatabase, name, config, false)
		}
	}
}
