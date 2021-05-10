package main

import (
	"flag"
	"log"
	"strings"

	"saasreconn/internal/api"
	"saasreconn/internal/db"
	"saasreconn/internal/provider"
)

const passiveConfidence = 1

func main() {

	// Read flags
	apikey := flag.String("vtotal-key", "", "VirusTotal API key")
	dataProviders := flag.String("dataproviders", "Crt.sh", "a comma separated list of passive data providers to use (supported providers: Crt.sh, VirusTotal, SearchDNS)")
	providerOnly := flag.String("provider", "", "query for a specific provider (use provider name from configuration)")
	endpointsConfig := flag.String("endpoints-config", "configs/saas-endpoints.yaml", "a SaaS providers endpoints file")
	verbose := flag.Int("verbose", 2, "verbosity factor")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	log.Println("Updating existing database")

	for name, data := range saasProviders {
		if *providerOnly != "" && name != *providerOnly {
			continue
		}
		for _, domain := range data.Subdomain {
			var found []string

			if strings.Contains(*dataProviders, "Crt.sh") {
				found = append(found, api.CrtShQuery(domain, *verbose)...)
				diff, _ := resultsDatabase.UpdateProvider(name, domain, db.MapStringNamesToSubdomain(found, passiveConfidence, "Crt.sh"))
				diff.Dump()
			}
			if strings.Contains(*dataProviders, "SearchDNS") {
				found = append(found, api.SearchDNSQuery(domain, "ends", *verbose)...)
				diff, _ := resultsDatabase.UpdateProvider(name, domain, db.MapStringNamesToSubdomain(found, passiveConfidence, "SearchDNS"))
				diff.Dump()
			}
			if strings.Contains(*dataProviders, "VirusTotal") {
				found = append(found, api.VirusTotalQuery(domain, *apikey, *verbose)...)
				diff, _ := resultsDatabase.UpdateProvider(name, domain, db.MapStringNamesToSubdomain(found, passiveConfidence, "VirusTotal"))
				diff.Dump()
			}
		}
	}
}
