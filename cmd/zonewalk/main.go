package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"saasreconn/pkg/db"
	"saasreconn/pkg/provider"
	"saasreconn/pkg/zonewalk"
)

const zoneWalkConfidence = 70

var defaultNameservers = []string{"208.67.222.222:53", "1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:%3"}

func runZoneWalking(resultsDatabase *db.Database, name string, config zonewalk.Config, nameservers []string) {
	for _, nameserver := range nameservers {
		config.Nameserver = nameserver
		found, isDNSSEC := zonewalk.AttemptWalk(config)
		if isDNSSEC {
			log.Printf("[%s:%s] Found %d names from DNSSEC zone-walking", name, config.Zone, len(found))
			diff, _ := resultsDatabase.UpdateProvider(name, config.Zone, db.MapStringNamesToSubdomain(found, zoneWalkConfidence))
			diff.Dump()
		}
	}

}

func main() {

	// Read flags
	endpointsConfig := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	listProviders := flag.Bool("list-providers", false, "list all supported providers")
	providerName := flag.String("provider", "", "run zone-walking for a specific provider")
	domain := flag.String("domain", "", "run zone-walking for a specific domain")
	nameserver := flag.String("nameserver", "", "run zone-walking for a specific nameserver")
	threads := flag.Int("threads", runtime.NumCPU(), "number of threads to use within the program (default is the logical number number of processors")
	timeout := flag.Int("timeout", 60, "number of seconds to run the zonewalk mapping for (default is 60)")
	walkmode := flag.Int("walkmode", 0, " what mode to use for zone-walking (0 for both mapping and reversing, 1 for just mapping and storing cache, and 2 for just reversing based on cache")
	noCache := flag.Bool("no-cache", false, "a bool whether to use pre-existing")
	hashcat := flag.Bool("hashcat", false, "use hashcat for reversing NSEC3 hashes")
	verbose := flag.Int("verbose", 3, "verbosity factor (default 3)")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}
	log.Println("Performing zone-walking")

	config := zonewalk.Config{
		Zone:       "",
		Nameserver: "",
		Threads:    *threads,
		Timeout:    *timeout,
		Cache:      !*noCache,
		Mode:       *walkmode,
		Hashcat:    *hashcat,
		Verbose:    *verbose,
	}

	nameservers := defaultNameservers
	if *nameserver != "" {
		nameservers = []string{*nameserver}
	}

	if *domain != "" {
		config.Zone = *domain
		runZoneWalking(resultsDatabase, *domain, config, nameservers)
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
			runZoneWalking(resultsDatabase, name, config, nameservers)
		}
	}
}
