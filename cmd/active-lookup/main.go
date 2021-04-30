package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"saasreconn/internal/checks"
	"saasreconn/internal/db"
	"saasreconn/internal/provider"
	"saasreconn/internal/tools"
)

const activePageValidConfidence = 80
const activePageInvalidConfidence = 30
const logoConfidence = 90

func main() {

	// Read flags
	cacheLifetime := flag.Float64("cache-lifetime", 48.0, "the lifetime of our HTTP requests cache (measured in hours)")
	endpointsConfig := flag.String("endpoints-config", "configs/saas-endpoints.yaml", "a SaaS providers endpoints file")
	noCache := flag.Bool("no-cache", false, "a bool whether to use pre-existing")
	parallelRequests := flag.Int("parallel-requests", 5, "how many HTTP requests should we issue in parallel")
	providerOnly := flag.String("provider", "", "do an active check for a specific SaaS provider")
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
			usedPrefixes = append(usedPrefixes, provider.ToPrefixString()...)
		}
		usedPrefixes = append(usedPrefixes, corporateName)
		usedPrefixes = tools.UniqueStrings(usedPrefixes)

		log.Printf("Found %d potential prefixes", len(usedPrefixes))
		var validDomainsCount, subdomainsDoneCount tools.AtomicCounter
		subdomainsOverallCount := 0

		// Validate possible domains
		var activeWorkers sync.WaitGroup
		checkingWorkers := make(chan bool, 5)
		for name, provider := range saasProviders {
			if len(*providerOnly) > 0 && name != *providerOnly {
				continue
			}
			subdomainsOverallCount += len(provider.Subdomain)
			for _, subdomain := range provider.Subdomain {
				activeWorkers.Add(1)
				go func(name string, subdomain string, usedPrefixes []string) {
					checkingWorkers <- true
					defer func() {
						<-checkingWorkers
					}()
					defer activeWorkers.Done()
					possibleNames := checks.SubdomainRange{
						Base:     checks.SubdomainBase(subdomain),
						Prefixes: usedPrefixes,
					}
					start := time.Now()
					validatedNames, invalidatedNames := possibleNames.Validate(checks.Config{
						Cache:         !*noCache,
						CacheLifetime: *cacheLifetime,
						Parallel:      *parallelRequests,
						Verbose:       *verbose,
					})
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
					validDomainsCount.IncrementCustom(len(updateDatabaseValid))
					subdomainsDoneCount.Increment()
					fmt.Printf("\rFinished examining %d/%d", subdomainsDoneCount.Read(), subdomainsOverallCount)
					if *verbose >= 3 {
						fmt.Println()
					}
				}(name, subdomain, usedPrefixes)
			}
			for _, url := range provider.Subdirectory {
				activeWorkers.Add(1)
				go func(name string, url string, usedPrefixes []string) {
					checkingWorkers <- true
					defer func() {
						<-checkingWorkers
					}()
					defer activeWorkers.Done()
					possibleNames := checks.SubdomainRange{
						Base:     checks.SubdirectoryBase(url),
						Prefixes: usedPrefixes,
					}
					start := time.Now()
					validatedNames, invalidatedNames := possibleNames.Validate(checks.Config{
						Cache:         !*noCache,
						CacheLifetime: *cacheLifetime,
						Parallel:      *parallelRequests,
						Verbose:       *verbose,
					})
					if *verbose >= 3 {
						fmt.Printf("[%s,%s] %d prefixes, %d valid, elapsed time %.2f seconds\n", name, url, len(possibleNames.Prefixes), len(validatedNames.Prefixes), time.Since(start).Seconds())
					}
					updateDatabaseValid := []string{}
					for _, prefix := range validatedNames.Prefixes {
						updateDatabaseValid = append(updateDatabaseValid, fmt.Sprintf("%s.%s", prefix, validatedNames.Base.GetBase()))
					}
					updateDatabaseInvalid := []string{}
					for _, prefix := range invalidatedNames.Prefixes {
						updateDatabaseInvalid = append(updateDatabaseInvalid, fmt.Sprintf("%s.%s", prefix, invalidatedNames.Base.GetBase()))
					}
					diff, _ := resultsDatabase.UpdateProvider(name, url, db.MapStringNamesToSubdomain(updateDatabaseValid, activePageValidConfidence, "Active validation"))
					if *verbose >= 3 {
						diff.Dump()
					}
					diff, _ = resultsDatabase.UpdateProvider(name, url, db.MapStringNamesToSubdomain(updateDatabaseInvalid, activePageInvalidConfidence, "Active validation"))
					if *verbose >= 3 {
						diff.Dump()
					}
					validDomainsCount.IncrementCustom(len(updateDatabaseValid))
					subdomainsDoneCount.Increment()
					fmt.Printf("\rFinished examining %d/%d", subdomainsDoneCount.Read(), subdomainsOverallCount)
					if *verbose >= 3 {
						fmt.Println()
					}
				}(name, url, usedPrefixes)
			}
		}
		log.Printf("About to examine %d subdomains issuing %d requests...", subdomainsOverallCount, subdomainsOverallCount*(len(usedPrefixes)+2))

		activeWorkers.Wait()
		fmt.Printf("\nFound %d active domains\n", validDomainsCount.Read())
	}

}
