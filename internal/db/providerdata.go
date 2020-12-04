package saasreconn

import (
	"json"
	"log"
	"regexp"
	"time"
)

type ProviderData struct {
	providerName string
	collected    time.Time
	subdomains   map[string][]string
}

func EmptyProviderData(providerName string) *ProviderData {
	return &ProviderData{
		providerName: providerName,
		collected:    time.Now(),
		subdomains:   make(map[string][]string),
	}
}

func ProvideDataFromJSON(data []byte) *ProviderData {
	providerData := new(ProviderData)
	err := json.Unmarshal(data, &providerData)
	if err != nil {
		log.Fatal("Invalid provider data")
		return EmptyProviderData(""), 1
	}

	return providerData
}

func (data *ProviderData) ToJSON() []byte {
	jsonOutput, err := json.Marshal(data)
	if err != nil {
		log.Fatal("Could not convert to JSON")
		return "", 1
	}

	return jsonOutput
}

func (data *ProviderData) query(domainPattern string) *ProviderData {

	domainsMap := make(map[string][]string)
	for rootDomain, subdomains := range data.subdomains {
		matchingDomains := []string{}
		for _, domain := range subdomains {
			matched, _ := regexp.MatchString(domainPattern, domain)
			if matched {
				matchingDomains = append(matchingDomains, domain)
			}
		}
		domainsMap[rootDomain] = matchingDomains
	}

	return &ProviderData{
		providerName: data.providerName,
		collected:    time.Now(),
		subdomains:   domainsMap,
	}
}

func (data *ProviderData) updateDomainEntries(rootDomain string, newSubdomains []string) {

	uniqueDomains := make(map[string]int)

	for _, domain := range data.subdomains[rootDomain] {
		uniqueDomains[domain] = 1
	}
	for _, domain := range newSubdomains {
		val, _ = uniqueDomains[domain]
		uniqueDomains[domain] = val + 2
	}
	
	addedDomains := []string{}
	removedDomains := []string{}
	allDomains := []string{}
	for domain, value := range uniqueDomains {
		if value == 1 {
			addedDomains = append(addedDomains, domain)
		}
		if value == 2 {
			removedDomains = append(removedDomains, domain)
		}
		allDomains = append(allDomains, domain)
	}

	data.subdomains[rootDomain] = allDomains

	return &DataDiff{
		added: addedDomains,
		removed: removedDomains
	}
}

func (providerData *ProviderData) dump() {
	log.Info("ProviderName: " + providerData.providerName + "\n");
	log.Info("Collected: " + providerData.collected.String() + "\n");
	for subdomain, data := range providerData.subdomains {
		log.Info("\t" + subdomain + ":\n");
		for _, data := range data {
			log.Info("\t\t" + data + "\n")
		}
	}
}
