package main

import (
	"flag"
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"

	"saasreconn/pkg/checks"
	"saasreconn/pkg/db"
	"saasreconn/pkg/provider"
	"saasreconn/pkg/report"
	"saasreconn/pkg/tools"
)

func passiveData(corporate string, db db.Database, providers map[string]provider.SaaSProvider) (providersData []db.ProviderData) {
	for providerName := range providers {
		providerData, _ := db.ProviderQuery(providerName, corporate)
		providersData = append(providersData, *providerData)
	}

	return providersData
}

const activePageConfidence = 80
const logoConfidence = 90

func main() {

	// Read flags
	endpointsConfig := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	passive := flag.Bool("passive", false, "a bool whether to run a passive scan")
	noCache := flag.Bool("no-cache", false, "a bool whether to use pre-existing")
	// timeout := flag.Int("timeout", 60, "a timeout for the active lookup")
	reportOnly := flag.Bool("report-only", false, "only generate the final report")
	confidenceThreshold := flag.Int("confidence-threshold", 70, "confidence treshold")
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
	for _, name := range argsWithoutProg {

		fmt.Println("Read \"" + name + "\"")
		if !*reportOnly {
			fmt.Println("Querying database...")

			providersData := passiveData(name, *resultsDatabase, saasProviders)
			if *passive {
				for _, provider := range providersData {
					provider.Dump()
				}
				continue
			}

			// Find prefixes
			usedPrefixes := []string{}
			for _, provider := range providersData {
				usedPrefixes = append(usedPrefixes, provider.AsString(true)...)
			}
			// TODO: maybe add some checks later
			usedPrefixes = append(usedPrefixes, name)
			usedPrefixes = append(usedPrefixes, name+".com")
			usedPrefixes = tools.UniqueStrings(usedPrefixes)

			log.Printf("Found %d potential prefixes", len(usedPrefixes))
			// Validate possible domains
			var activeWorkers sync.WaitGroup
			for name, provider := range saasProviders {
				for _, subdomain := range provider.Subdomain {
					activeWorkers.Add(1)
					go func(name string, subdomain string, usedPrefixes []string) {
						defer activeWorkers.Done()
						possibleNames := checks.SubdomainRange{
							Base:     checks.SubdomainBase(subdomain),
							Prefixes: usedPrefixes,
						}
						start := time.Now()
						validatedNames := possibleNames.Validate(*noCache, *verbose)
						// potentialSubdomans <- validatedNames
						if *verbose >= 2 {
							fmt.Printf("[%s,%s] %d prefixes, %d valid, elapsed time %.2f seconds\n", name, subdomain, len(possibleNames.Prefixes), len(validatedNames.Prefixes), time.Since(start).Seconds())
						}
						updateDatabase := []string{}
						for _, prefix := range validatedNames.Prefixes {
							updateDatabase = append(updateDatabase, fmt.Sprintf("%s.%s", prefix, validatedNames.Base.GetBase()))
						}
						diff, _ := resultsDatabase.UpdateProvider(name, subdomain, db.MapStringNamesToSubdomain(updateDatabase, activePageConfidence, "Active validation"))
						diff.Dump()
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

			activeWorkers.Wait()
		}
		fmt.Printf("Generating HTML report for \"%s\"\n", name)
		start := time.Now()
		exportedSubdomains := []report.ExposedSubdomains{}
		for providerName := range saasProviders {
			providerData, _ := resultsDatabase.ProviderQuery(providerName, name)
			readySubdomain := make(chan report.SubdomainRow)
			var subdomainWorkers sync.WaitGroup
			for _, subdomains := range providerData.Subdomains {
				for _, subdomain := range subdomains {
					if subdomain.Confidence < *confidenceThreshold {
						continue
					}
					subdomainWorkers.Add(1)
					go func(subdomain db.Subdomain, subdomainWorkers *sync.WaitGroup) {
						defer subdomainWorkers.Done()
						fmt.Printf("Started with %s\n", subdomain.Name)
						subdomainInfo := report.SubdomainRow{
							Subdomain:  subdomain.Name,
							Confidence: subdomain.Confidence,
							FoundIn:    subdomain.DiscoveredBy,
							Screenshot: checks.ImageFromURL(tools.URLFromSubdomainEntry(subdomain.Name)),
						}
						readySubdomain <- subdomainInfo
						fmt.Printf("Finished with %s\n", subdomain.Name)
					}(subdomain, &subdomainWorkers)
				}
			}
			var subdomainList []report.SubdomainRow
			go func() {
				for {
					subdomain, more := <-readySubdomain
					if !more {
						return
					}
					subdomainList = append(subdomainList, subdomain)
				}
			}()

			subdomainWorkers.Wait()
			close(readySubdomain)
			exportedSubdomains = append(exportedSubdomains,
				report.ExposedSubdomains{
					Provider:   providerName,
					Subdomains: subdomainList,
				})
		}
		timestamp := time.Now().Format(time.RFC3339)
		re := regexp.MustCompile(`-|:|`)
		timestamp = re.ReplaceAllString(timestamp, "")
		report.ExportToHTML(exportedSubdomains, name, fmt.Sprintf("%s-%s", name, timestamp))
		fmt.Printf("HTML generation took %s\n", time.Since(start))
		// Check logos and other specific features
		// if *logoCheck {
		// 	test := checks.DetectLogosInUrl("http://intel.box.com")
		// 	log.Printf("Found %v", test)
		// }
	}

}
