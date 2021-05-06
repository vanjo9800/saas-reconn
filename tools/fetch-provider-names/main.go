package main

import (
	"flag"
	"fmt"
	"saasreconn/internal/db"
	"saasreconn/internal/tools"
)

func filterConfidence(foundSubdomains map[string][]db.Subdomain, confidenceThreshold int) map[string][]db.Subdomain {
	domainsReport := make(map[string][]db.Subdomain)
	for record, subdomains := range foundSubdomains {
		filteredSubdomainsForRecord := []db.Subdomain{}
		for _, subdomain := range subdomains {
			if subdomain.Confidence >= confidenceThreshold {
				filteredSubdomainsForRecord = append(filteredSubdomainsForRecord, subdomain)
			}
		}
		domainsReport[record] = filteredSubdomainsForRecord
	}
	return domainsReport
}

func main() {
	provider := flag.String("provider", "", "provider name")
	confidenceLevel := flag.Int("conf-level", 3, "minimal confidence score")
	flag.Parse()

	resultsDatabase := db.NewDatabase()
	providerData, _ := resultsDatabase.ProviderQuery(*provider, tools.ProviderDomainRegex(".*", true))
	filtered := filterConfidence(providerData.Subdomains, *confidenceLevel)
	for _, name := range db.NamesFromProviderData([]db.ProviderData{{
		Subdomains: filtered,
	}}) {
		fmt.Println(name)
	}
}
