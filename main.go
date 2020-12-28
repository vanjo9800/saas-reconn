package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"saasreconn/internal/api"
	"saasreconn/internal/checks"
	"saasreconn/internal/db"
	"saasreconn/internal/provider"
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
	enum := flag.Bool("enum", false, "a bool whether to enumerate domains from various online sources")
	passive := flag.Bool("passive", false, "a bool whether to run a passive scan")
	endpoints := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	// apiCredentials := flag.String("api-credentials", "configs/credentials.yaml", "online APIs credentials")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpoints)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	if *enum {
		log.Println("Updating existing database")

		log.Println("Updating JSON files")
		for name, data := range saasProviders {
			for _, domain := range data.Subdomain {
				found := api.CrtShQuery(domain)
				// found = append(found, api.SearchDNSQuery(domain, "ends")...)
				diff, _ := resultsDatabase.UpdateProvider(name, domain, found)
				diff.Dump()
			}
		}

		os.Exit(0)

	}

	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		log.Fatalln("Please enter at least one corporate name to scan for.")
	}
	for _, name := range argsWithoutProg {
		fmt.Println("Read \"" + name + "\". Querying database...")

		providersData := passiveData(name, *resultsDatabase, saasProviders)
		if *passive {
			for _, provider := range providersData {
				provider.Dump()
			}
		} else {
			usedPrefixes := []string{}
			for _, provider := range providersData {
				usedPrefixes = append(usedPrefixes, provider.AsString(true)...)
			}
			// Check resolves
			resolvableNames := map[string]checks.SubdomainRange{}
			for name, provider := range saasProviders {
				for _, subdomain := range provider.Subdomain {
					possibleNames := checks.SubdomainRange{
						Base:     subdomain,
						Prefixes: usedPrefixes,
					}
					resolvableNames[subdomain] = possibleNames.Resolvable()
					log.Printf("[%s] %d prefixes, %d resolvable", name, len(possibleNames.Prefixes), len(resolvableNames[subdomain].Prefixes))
				}
			}
			// Check different than example page
			uniqueNames := map[string]checks.SubdomainRange{}
			for name, provider := range saasProviders {
				for _, subdomain := range provider.Subdomain {
					uniqueNames[subdomain] = resolvableNames[subdomain].UniquePage()
					log.Printf("[%s] %d resolvable, %d unique", name, len(resolvableNames[subdomain].Prefixes), len(uniqueNames[subdomain].Prefixes))
				}
			}
			for _, ranges := range uniqueNames {
				ranges.Dump()
			}
			// Check logos and other specific features
		}
	}

}
