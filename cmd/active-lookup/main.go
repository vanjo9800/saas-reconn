package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"saasreconn/pkg/checks"
	"saasreconn/pkg/db"
	"saasreconn/pkg/provider"
	"saasreconn/pkg/tools"
)

const activePageValidConfidence = 80
const activePageInvalidConfidence = 30
const logoConfidence = 90

func main() {

	// Read flags
	endpointsConfig := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	noCache := flag.Bool("no-cache", false, "a bool whether to use pre-existing")
	// timeout := flag.Int("timeout", 60, "a timeout for the active lookup")
	// logoCheck := flag.Bool("logocheck", false, "whether to check logos")
	verbose := flag.Int("verbose", 2, "verbosity factor")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	argsWithoutProg := flag.Args()
	if len(argsWithoutProg) == 0 {
		log.Fatalln("Please enter at least one corporate name to scan for.")
	}
	for _, corporateName := range argsWithoutProg {

		fmt.Printf("Read \"%s\"\n", corporateName)
		fmt.Println("Querying database...")

		var storedData []db.ProviderData
		for providerName := range saasProviders {
			providerData, _ := resultsDatabase.ProviderQuery(providerName, tools.ProviderDomainRegex(corporateName, true))
			storedData = append(storedData, *providerData)
		}

		// Find prefixes
		usedPrefixes := []string{}
		for _, provider := range storedData {
			usedPrefixes = append(usedPrefixes, provider.AsString(true)...)
		}
		usedPrefixes = append(usedPrefixes, corporateName)
		usedPrefixes = tools.UniqueStrings(usedPrefixes)

		log.Printf("Found %d potential prefixes", len(usedPrefixes))
		var subdomainDoneCountLock sync.Mutex
		subdomainsDoneCount, subdomainsOverallCount := 0, 0
		var validCountLock sync.Mutex
		validDomainsCount := 0
		// Validate possible domains
		var activeWorkers sync.WaitGroup
		for name, provider := range saasProviders {
			subdomainsOverallCount += len(provider.Subdomain)
			for _, subdomain := range provider.Subdomain {
				activeWorkers.Add(1)
				go func(name string, subdomain string, usedPrefixes []string) {
					defer activeWorkers.Done()
					possibleNames := checks.SubdomainRange{
						Base:     checks.SubdomainBase(subdomain),
						Prefixes: usedPrefixes,
					}
					start := time.Now()
					validatedNames, invalidatedNames := possibleNames.Validate(*noCache, *verbose)
					if *verbose >= 3 {
						fmt.Printf("[%s,%s] %d prefixes, %d valid, elapsed time %.2f seconds\n", name, subdomain, len(possibleNames.Prefixes), len(validatedNames.Prefixes), time.Since(start).Seconds())
					}
					updateDatabaseValid := []string{}
					for _, prefix := range validatedNames.Prefixes {
						updateDatabaseValid = append(updateDatabaseValid, fmt.Sprintf("%s.%s", prefix, validatedNames.Base.GetBase()))
					}
					updateDatabaseInvalid := []string{}
					for _, prefix := range invalidatedNames.Prefixes {
						updateDatabaseInvalid = append(updateDatabaseInvalid, fmt.Sprintf("%s.%s", prefix, invalidatedNames.Base.GetBase()))
					}
					diff, _ := resultsDatabase.UpdateProvider(name, subdomain, db.MapStringNamesToSubdomain(updateDatabaseValid, activePageValidConfidence, "Active validation"))
					if *verbose >= 3 {
						diff.Dump()
					}
					diff, _ = resultsDatabase.UpdateProvider(name, subdomain, db.MapStringNamesToSubdomain(updateDatabaseInvalid, activePageInvalidConfidence, "Active validation"))
					if *verbose >= 3 {
						diff.Dump()
					}
					validCountLock.Lock()
					validDomainsCount += len(updateDatabaseValid)
					validCountLock.Unlock()
					subdomainDoneCountLock.Lock()
					subdomainsDoneCount++
					fmt.Printf("\rFinished examining %d/%d", subdomainsDoneCount, subdomainsOverallCount)
					subdomainDoneCountLock.Unlock()
				}(name, subdomain, usedPrefixes)
			}
			// for _, url := range provider.Urls {
			// 	possibleNames := checks.SubdomainRange{
			// 		Base:     checks.UrlBase(url),
			// 		Prefixes: usedPrefixes,
			// 	}
			// 	validNames[url] = possibleNames.Validate(*noCache, *verbose)
			// 	if *verbose >= 2 {
			// 		log.Printf("[%s] %d prefixes, %d valid", name, len(possibleNames.Prefixes), len(validNames[url].Prefixes))
			// 	}
			// }
		}
		log.Printf("About to examine %d subdomains issuing %d requests...", subdomainsOverallCount, subdomainsOverallCount*(len(usedPrefixes)+2))

		activeWorkers.Wait()
		fmt.Printf("\nFound %d active domains\n", validDomainsCount)
		// Check logos and other specific features
		// if *logoCheck {
		// 	test := checks.DetectLogosInUrl("http://intel.box.com")
		// 	log.Printf("Found %v", test)
		// }
	}

}
