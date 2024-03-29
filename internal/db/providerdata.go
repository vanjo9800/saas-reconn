package db

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"saasreconn/internal/tools"
	"sort"
	"time"
)

// ProviderData is the major class that stores data from service providers
type ProviderData struct {
	Provider   string
	Collected  time.Time
	Subdomains map[string][]Subdomain
}

// Subdomain is a class of stored subdomain entry with a name and a confidence score
type Subdomain struct {
	Name         string
	Confidence   int
	DiscoveredBy []string
	Screenshot   string
}

// ToString is a helper method which converts a ProviderData object into a string
func (data *ProviderData) ToString() string {
	result := fmt.Sprintf("ProviderName: %s\n", data.Provider)
	result = result + fmt.Sprintf("Collected: %s\n", data.Collected.String())
	for subdomain, domainsArray := range data.Subdomains {
		if len(domainsArray) == 0 {
			continue
		}
		result = result + fmt.Sprintf("  - %s\n", subdomain)
		for _, domain := range domainsArray {
			result = result + fmt.Sprintf("    - %s, conf. %d, sources %v\n", domain.Name, domain.Confidence, domain.DiscoveredBy)
		}
	}
	return result
}

func (data *ProviderData) IsEqual(data2 *ProviderData) bool {
	return data.ToString() == data2.ToString()
}

// EmptyProviderData returns an empty data object, usually when we have no data stored for the provider
func EmptyProviderData(providerName string) *ProviderData {
	return &ProviderData{
		Provider:   providerName,
		Collected:  time.Now(),
		Subdomains: make(map[string][]Subdomain),
	}
}

// MapStringNamesToSubdomain applies a certain confidence score to a string array of subdomains
func MapStringNamesToSubdomain(domainNames []string, confidenceScore int, source string) (domains []Subdomain) {
	for _, domainName := range domainNames {
		domains = append(domains, Subdomain{
			Name:         tools.CleanDomainName(domainName),
			Confidence:   confidenceScore,
			DiscoveredBy: []string{source},
		})
	}

	return domains
}

func NamesFromProviderData(providerData []ProviderData) (names []string) {
	for _, providerSubdomains := range providerData {
		for _, subdomains := range providerSubdomains.Subdomains {
			for _, subdomain := range subdomains {
				names = append(names, subdomain.Name)
			}
		}
	}

	return names
}

// ToPrefixString is a helper method that converts a ProviderData object into a string of subdomains
func (data *ProviderData) ToPrefixString() (subdomains []string) {
	for subdomain, domainsArray := range data.Subdomains {
		for _, domain := range domainsArray {
			subdomains = append(subdomains, tools.GetSubdomainPrefix(domain.Name, subdomain))
		}
	}

	return subdomains
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
		Provider:   data.Provider,
		Collected:  time.Now(),
		Subdomains: domainsMap,
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

	sort.SliceStable(data.Subdomains[rootDomain], func(i, j int) bool {
		if data.Subdomains[rootDomain][i].Confidence == data.Subdomains[rootDomain][j].Confidence {
			return data.Subdomains[rootDomain][i].Name < data.Subdomains[rootDomain][j].Name
		}
		return data.Subdomains[rootDomain][i].Confidence > data.Subdomains[rootDomain][j].Confidence
	})
	sort.SliceStable(addedDomains, func(i, j int) bool {
		if addedDomains[i].Confidence == addedDomains[j].Confidence {
			return addedDomains[i].Name < addedDomains[j].Name
		}
		return addedDomains[i].Confidence > addedDomains[j].Confidence
	})

	return &DataDiff{
		added: addedDomains,
	}
}

// ProviderDataFromJSON parses a JSON stored data into the ProviderData object
func ProviderDataFromJSON(data []byte) (providerData *ProviderData, err error) {
	providerData = new(ProviderData)
	err = json.Unmarshal(data, &providerData)
	if err != nil {
		log.Printf("[%s] Invalid provider data: %s", providerData.Provider, err)
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
