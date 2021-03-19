package db

import (
	"encoding/json"
	"log"
	"regexp"
	"saasreconn/pkg/tools"
	"sort"
	"strings"
	"time"
)

// ProviderData is the major class that stores data from service providers
type ProviderData struct {
	ProviderName string
	Collected    time.Time
	Subdomains   map[string][]Subdomain
}

// Subdomain is a class of stored subdomain entry with a name and a confidence score
type Subdomain struct {
	Name         string
	Confidence   int
	DiscoveredBy []string
}

// SubdomainList is an instance of list of Subdomains with defined comparison functions
type SubdomainList []Subdomain

func (l SubdomainList) Len() int { return len(l) }
func (l SubdomainList) Less(i, j int) bool {
	if l[i].Confidence == l[j].Confidence {
		return l[i].Name < l[j].Name
	}
	return l[i].Confidence > l[j].Confidence
}
func (l SubdomainList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

// MapStringNamesToSubdomain applies a certain confidence score to a string array of subdomains
func MapStringNamesToSubdomain(domainNames []string, confidenceScore int, source string) (domains []Subdomain) {
	for _, domainName := range domainNames {
		domains = append(domains, Subdomain{
			Name:         domainName,
			Confidence:   confidenceScore,
			DiscoveredBy: []string{source},
		})
	}

	return domains
}

// EmptyProviderData returns an empty data object, usually when we have no data stored for the provider
func EmptyProviderData(providerName string) *ProviderData {
	return &ProviderData{
		ProviderName: providerName,
		Collected:    time.Now(),
		Subdomains:   make(map[string][]Subdomain),
	}
}

// ProviderDataFromJSON parses a JSON stored data into the ProviderData object
func ProviderDataFromJSON(data []byte) (providerData *ProviderData, err error) {
	providerData = new(ProviderData)
	err = json.Unmarshal(data, &providerData)
	if err != nil {
		log.Printf("[%s] Invalid provider data: %s", providerData.ProviderName, err)
		return EmptyProviderData(""), err
	}

	return providerData, err
}

// ToJSON outputs the current ProviderData object as a JSON byte string
func (data *ProviderData) ToJSON() (bytes []byte, err error) {
	jsonOutput, err := json.Marshal(data)
	if err != nil {
		log.Printf("Could not convert to JSON")
		return nil, err
	}

	return jsonOutput, err
}

func (data *ProviderData) query(domainPattern string) *ProviderData {

	domainsMap := make(map[string][]Subdomain)
	for rootDomain, subdomains := range data.Subdomains {
		matchingDomains := []Subdomain{}
		for _, domain := range subdomains {
			matched, _ := regexp.MatchString(domainPattern, domain.Name)
			if matched {
				matchingDomains = append(matchingDomains, domain)
			}
		}
		domainsMap[rootDomain] = matchingDomains
	}

	return &ProviderData{
		ProviderName: data.ProviderName,
		Collected:    time.Now(),
		Subdomains:   domainsMap,
	}
}

func (data *ProviderData) updateDomainEntries(rootDomain string, newSubdomains []Subdomain) *DataDiff {

	var addedDomains []Subdomain
	uniqueDomains := make(map[string]int)
	sourcesDomains := make(map[string][]string)

	for _, domain := range data.Subdomains[rootDomain] {
		uniqueDomains[domain.Name] = domain.Confidence
		sourcesDomains[domain.Name] = domain.DiscoveredBy
	}
	for _, domain := range newSubdomains {
		if _, ok := uniqueDomains[domain.Name]; !ok {
			addedDomains = append(addedDomains, domain)
		}
		uniqueDomains[domain.Name] = domain.Confidence
		sourcesDomains[domain.Name] = tools.UniqueStrings(append(sourcesDomains[domain.Name], domain.DiscoveredBy...))
	}

	data.Subdomains[rootDomain] = []Subdomain{}
	for name, confidence := range uniqueDomains {
		data.Subdomains[rootDomain] = append(data.Subdomains[rootDomain], Subdomain{
			Name:         name,
			Confidence:   confidence,
			DiscoveredBy: sourcesDomains[name],
		})
	}

	sort.Sort(SubdomainList(data.Subdomains[rootDomain]))
	sort.Sort(SubdomainList(addedDomains))

	return &DataDiff{
		added: addedDomains,
	}
}

// AsString is a helper method that converts a ProviderData object into a string of subdomains
func (data *ProviderData) AsString(onlyPrefix bool) (subdomains []string) {
	for subdomain, domainsArray := range data.Subdomains {
		for _, domain := range domainsArray {
			if onlyPrefix {
				subdomains = append(subdomains, strings.TrimSuffix(domain.Name, "."+subdomain))
			} else {
				subdomains = append(subdomains, domain.Name)
			}
		}
	}

	return subdomains
}

// Dump is a helper method which prints the whole ProviderData object
func (data *ProviderData) Dump() {
	printedIntro := 0
	for subdomain, domainsArray := range data.Subdomains {
		if len(domainsArray) == 0 {
			continue
		}
		if printedIntro == 0 {
			log.Printf("ProviderName: %s\n", data.ProviderName)
			log.Printf("Collected: %s\n", data.Collected.String())
			printedIntro = 1
		}
		log.Println("  - " + subdomain)
		for _, domain := range domainsArray {
			log.Printf("    - %s, conf. %d, sources %v", domain.Name, domain.Confidence, domain.DiscoveredBy)
		}
	}
}
