package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"saasreconn/pkg/api"
	"saasreconn/pkg/checks"
	"saasreconn/pkg/db"
	"saasreconn/pkg/dns"
	"saasreconn/pkg/provider"
)

func passiveData(corporate string, db db.Database, providers map[string]provider.SaaSProvider) (providersData []db.ProviderData) {
	for providerName := range providers {
		providerData, _ := db.ProviderQuery(providerName, corporate)
		providersData = append(providersData, *providerData)
	}

	return providersData
}

func main() {

	// Read flags
	threads := flag.Int("threads", runtime.NumCPU(), "number of threads to use within the program (default is the logical number number of processors")
	timeout := flag.Int("timeout", 60, "number of seconds to run the zonewalk mapping for (default is 60)")
	enum := flag.Bool("enum", false, "a bool whether to enumerate domains from various online sources")
	zonewalk := flag.Bool("zonewalk", false, "a bool whether to perform DNS zone-walking on existing providers and expand the passive database")
	passive := flag.Bool("passive", false, "a bool whether to run a passive scan")
	noCache := flag.Bool("no-cache", false, "a bool whether to use pre-existing")
	dataProviders := flag.String("dataproviders", "Crt.sh", "a comma separated list of passive data providers to use (default Crt.sh)")
	endpointsConfig := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	apikey := flag.String("apikey", "", "VirusTotal API key")
	// apiCredentials := flag.String("api-credentials", "configs/credentials.yaml", "online APIs credentials")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	if *enum {
		log.Println("Updating existing database")

		for name, data := range saasProviders {
			for _, domain := range data.Subdomain {
				found := []string{}

				if strings.Contains(*dataProviders, "Crt.sh") {
					found = append(found, api.CrtShQuery(domain)...)
				}
				if strings.Contains(*dataProviders, "SearchDNS") {
					found = append(found, api.SearchDNSQuery(domain, "ends")...)
				}
				if strings.Contains(*dataProviders, "VirusTotal") {
					found = append(found, api.VirusTotalQuery(domain, *apikey)...)
				}
				diff, _ := resultsDatabase.UpdateProvider(name, domain, found)
				diff.Dump()
			}
		}

		os.Exit(0)
	}

	if *zonewalk {
		log.Println("Performing zone-walking")

		nameservers := []string{"208.67.222.222", "1.1.1.1", "8.8.8.8", "8.8.4.4"}
		for name, data := range saasProviders {
			for _, domain := range data.Subdomain {
				for _, nameserver := range nameservers {
					found, isDNSSEC := dns.ZoneWalkAttempt(domain, nameserver, 53, *threads, *timeout, *noCache)
					if isDNSSEC {
						log.Printf("[%s:%s] Found %d names from DNSSEC zone-walking", name, domain, len(found))
						diff, _ := resultsDatabase.UpdateProvider(name, domain, found)
						diff.Dump()
					}
				}
			}
		}
		os.Exit(0)
	}

	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		log.Fatalln("Please enter at least one corporate name to scan for.")
	}
	for _, name := range argsWithoutProg {
		if strings.HasPrefix(name, "-") {
			continue
		}

		fmt.Println("Read \"" + name + "\". Querying database...")

		providersData := passiveData(name, *resultsDatabase, saasProviders)
		if *passive {
			for _, provider := range providersData {
				provider.Dump()
			}
		} else {
			// Find prefixes
			usedPrefixes := []string{}
			for _, provider := range providersData {
				usedPrefixes = append(usedPrefixes, provider.AsString(true)...)
			}
			// TODO: maybe add some checks later
			usedPrefixes = append(usedPrefixes, name)
			usedPrefixes = append(usedPrefixes, name+".com")

			// Validate possible domains
			validNames := map[string]checks.SubdomainRange{}
			for name, provider := range saasProviders {
				for _, subdomain := range provider.Subdomain {
					possibleNames := checks.SubdomainRange{
						Base:     checks.SubdomainBase(subdomain),
						Prefixes: usedPrefixes,
					}
					validNames[subdomain] = possibleNames.Validate(*noCache)
					log.Printf("[%s] %d prefixes, %d valid", name, len(possibleNames.Prefixes), len(validNames[subdomain].Prefixes))
					updateDatabase := []string{}
					for _, prefix := range validNames[subdomain].Prefixes {
						updateDatabase = append(updateDatabase, fmt.Sprintf("%s.%s", prefix, validNames[subdomain].Base.GetBase()))
					}
					diff, _ := resultsDatabase.UpdateProvider(name, subdomain, updateDatabase)
					diff.Dump()
				}
				for _, url := range provider.Urls {
					possibleNames := checks.SubdomainRange{
						Base:     checks.UrlBase(url),
						Prefixes: usedPrefixes,
					}
					validNames[url] = possibleNames.Validate(*noCache)
					log.Printf("[%s] %d prefixes, %d valid", name, len(possibleNames.Prefixes), len(validNames[url].Prefixes))
				}
			}

			for _, ranges := range validNames {
				ranges.Dump()
			}
			// Check logos and other specific features
		}
	}

}
