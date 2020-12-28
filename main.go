package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"saasreconn/internal/api"
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
	// passive := flag.Bool("passive", false, "a bool whether to run a passive scan")
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
	for _, name := range argsWithoutProg {
		fmt.Println("Read \"" + name + "\". Querying database...")

		// if *passive {
		providersData := passiveData(name, *resultsDatabase, saasProviders)
		for _, provider := range providersData {
			provider.Dump()
		}
		// } else {

		// }
	}

}
