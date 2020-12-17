package db

import (
	"encoding/json"
	"log"
	"regexp"
	"time"
)

// ProviderData is the major class that stores data from service providers
type ProviderData struct {
	ProviderName string
	Collected    time.Time
	Subdomains   map[string][]string
}

// EmptyProviderData returns an empty data object, usually when we have no data stored for the provider
func EmptyProviderData(providerName string) *ProviderData {
	return &ProviderData{
		ProviderName: providerName,
		Collected:    time.Now(),
		Subdomains:   make(map[string][]string),
	}
}

// ProviderDataFromJSON parses a JSON stored data into the ProviderData object
func ProviderDataFromJSON(data []byte) (providerData *ProviderData, err error) {
	providerData = new(ProviderData)
	err = json.Unmarshal(data, &providerData)
	if err != nil {
		log.Fatal("Invalid provider data")
		return EmptyProviderData(""), err
	}

	return providerData, err
}

// ToJSON outputs the current ProviderData object as a JSON byte string
func (data *ProviderData) ToJSON() (bytes []byte, err error) {
	jsonOutput, err := json.Marshal(data)
	if err != nil {
		log.Fatal("Could not convert to JSON")
		return nil, err
	}

	return jsonOutput, err
}

func (data *ProviderData) query(domainPattern string) *ProviderData {

	domainsMap := make(map[string][]string)
	for rootDomain, subdomains := range data.Subdomains {
		matchingDomains := []string{}
		for _, domain := range subdomains {
			matched, _ := regexp.MatchString(domainPattern, domain)
			if matched {
				matchingDomains = append(matchingDomains, domain)
			}
		}
		domainsMap[rootDomain] = matchingDomains
	}
	log.Println("matched: " + " " + domainPattern)

	return &ProviderData{
		ProviderName: data.ProviderName,
		Collected:    time.Now(),
		Subdomains:   domainsMap,
	}
}

func (data *ProviderData) updateDomainEntries(rootDomain string, newSubdomains []string) *DataDiff {

	uniqueDomains := make(map[string]int)

	for _, domain := range data.Subdomains[rootDomain] {
		uniqueDomains[domain] = 1
	}
	for _, domain := range newSubdomains {
		val, _ := uniqueDomains[domain]
		uniqueDomains[domain] = val + 2
	}

	addedDomains := []string{}
	removedDomains := []string{}
	allDomains := []string{}
	for domain, value := range uniqueDomains {
		if value == 2 {
			addedDomains = append(addedDomains, domain)
		}
		if value == 1 {
			removedDomains = append(removedDomains, domain)
		}
		allDomains = append(allDomains, domain)
	}

	data.Subdomains[rootDomain] = allDomains

	return &DataDiff{
		added:   addedDomains,
		removed: removedDomains,
	}
}

// Dump is a helper function which prints the whole ProviderData object
func (data *ProviderData) Dump() {
	log.Println("ProviderName: " + data.ProviderName)
	log.Println("Collected: " + data.Collected.String())
	for subdomain, domainsArray := range data.Subdomains {
		if len(domainsArray) == 0 {
			continue
		}
		log.Println("\t- " + subdomain)
		for _, domain := range domainsArray {
			log.Println("\t\t- " + domain)
		}
	}
}
