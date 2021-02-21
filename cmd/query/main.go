package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"saasreconn/pkg/checks"
	"saasreconn/pkg/db"
	"saasreconn/pkg/provider"
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
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
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
					diff, _ := resultsDatabase.UpdateProvider(name, subdomain, db.MapStringNamesToSubdomain(updateDatabase, activePageConfidence))
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
