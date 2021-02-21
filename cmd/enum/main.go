package main

import (
	"flag"
	"log"
	"strings"

	"saasreconn/pkg/api"
	"saasreconn/pkg/db"
	"saasreconn/pkg/provider"
)

const passiveConfidence = 60

func main() {

	// Read flags
	endpointsConfig := flag.String("endpoints-config", "configs/saas_endpoints.yaml", "a SaaS providers endpoints file")
	dataProviders := flag.String("dataproviders", "Crt.sh", "a comma separated list of passive data providers to use (default Crt.sh)")
	apikey := flag.String("vtotal-key", "", "VirusTotal API key")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	log.Println("Updating existing database")

	for name, data := range saasProviders {
		for _, domain := range data.Subdomain {
			var found []string

			if strings.Contains(*dataProviders, "Crt.sh") {
				found = append(found, api.CrtShQuery(domain)...)
			}
			if strings.Contains(*dataProviders, "SearchDNS") {
				found = append(found, api.SearchDNSQuery(domain, "ends")...)
			}
			if strings.Contains(*dataProviders, "VirusTotal") {
				found = append(found, api.VirusTotalQuery(domain, *apikey)...)
			}
			diff, _ := resultsDatabase.UpdateProvider(name, domain, db.MapStringNamesToSubdomain(found, passiveConfidence))
			diff.Dump()
		}
	}
}
