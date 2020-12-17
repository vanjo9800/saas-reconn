package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/systems"

	"saasreconn/internal/api"
	"saasreconn/internal/db"

	// "saasreconn/internal/dns"
	"saasreconn/internal/provider"
)

func nameToHosts() {

}

func hostsEnumeration(cfg *config.Config) []string {
	// Setup enumeration (from different lists)
	results := []string{}

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return results
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys, true))

	e := enum.NewEnumeration(cfg, sys)
	if e == nil {
		return results
	}
	defer e.Close()

	e.Start()
	for _, o := range e.ExtractOutput(nil, false) {
		results = append(results, o.Name)
	}

	sort.Strings(results)
	return results
}

func hostsDNS() {

}

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// Read flags
	enum := flag.Bool("enum", false, "a bool whether to enumerate domains from various online sources")
	timeout := flag.Int("timeout", 1, "enumeration process timeout")
	// intel := flag.Bool("intel", false, "a bool whether to do an intelligence search based on given corporate name")
	dns := flag.Bool("dns", false, "a bool whether to run special DNS enumeration methods")
	static := flag.Bool("static", false, "a bool whether to run a fully static scan")
	endpoints := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	apiCredentials := flag.String("api-credentials", "configs/credentials.yaml", "online APIs credentials")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpoints)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	if *enum {
		log.Println("Updating existing database")
		cfg := config.NewConfig()
		cfg.Verbose = true
		cfg.Active = !*static
		cfg.Log = log.New(os.Stderr, "Enumeration info: ", log.Ldate|log.Ltime|log.Lshortfile)
		cfg.Timeout = *timeout
		cfg.MaxDNSQueries = 5
		cfg.Ports = []int{25, 443, 567, 993}
		cfg.Resolvers = []string{"8.8.8.8", "1.1.1.1"}

		api.SetupAPICredentials(cfg, *apiCredentials)

		log.Println("Adding domains to configuration")
		// Setup the most basic amass configuration
		for _, data := range saasProviders {
			for _, domain := range data.Subdomain {
				cfg.AddDomain(domain)
			}
		}

		log.Println("Starting enumeration...")
		found := make(map[string][]string)
		for _, foundDomain := range hostsEnumeration(cfg) {
			found[cfg.WhichDomain(foundDomain)] = append(found[cfg.WhichDomain(foundDomain)], foundDomain)
		}

		log.Println("Updating JSON files")
		for name, data := range saasProviders {
			for _, domain := range data.Subdomain {
				diff, _ := resultsDatabase.UpdateProvider(name, domain, found[domain])
				diff.Dump()
			}
		}

		os.Exit(0)

	}

	if *dns {
		// dns.RunDNSCommand("nlnetlabs.nl")

		os.Exit(0)
	}

	argsWithoutProg := os.Args[1:]
	for _, name := range argsWithoutProg {
		fmt.Println("Read \"" + name + "\". Querying database...")
		for providerName := range saasProviders {
			providerData, _ := resultsDatabase.ProviderQuery(providerName, name)
			providerData.Dump()
		}
	}

}
