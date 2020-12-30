package checks

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"
)

func cleanResponse(responseBody string, hostname string) string {
	cleanBody := responseBody

	// Remove the hostname
	reg := regexp.MustCompile(`\Q` + hostname + `\E`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	// Remove base URL in Okta response
	reg = regexp.MustCompile(`baseUrl\s=\s'.*?'`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	// Remove ID comment in Slack response
	reg = regexp.MustCompile(`<!--\sslack-www.*? -->`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	// Remove ID's in OneLogin response
	reg = regexp.MustCompile(`NREUM.info={.*?}|value="[\da-zA-Z/=+]+"`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	// Remove requestToken in Box response
	reg = regexp.MustCompile(`requestToken\s=\s'[a-zA-Z\d]+'`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	return cleanBody
}

func (checkRange SubdomainRange) Validate(noCache bool) (validRange SubdomainRange) {
	validRange.Base = checkRange.Base

	randomHostname1 := fmt.Sprintf("hdmmndjzsj.%s", checkRange.Base)
	randomHostname2 := fmt.Sprintf("wbuiiionia.%s", checkRange.Base)

	existsErrorPage := true
	errorPageClean := ""
	resp, err := http.Get(fmt.Sprintf("http://%s/", randomHostname1))
	if err != nil {
		log.Printf("[%s] Could not access random subdomain page, domain must be existing", checkRange.Base)
		existsErrorPage = false
	}
	if existsErrorPage {
		defer resp.Body.Close()
		errorPage, _ := ioutil.ReadAll(resp.Body)
		errorPageClean = cleanResponse(string(errorPage), randomHostname1)
		resp, _ = http.Get(fmt.Sprintf("http://%s/", randomHostname2))
		defer resp.Body.Close()
		errorPage, _ = ioutil.ReadAll(resp.Body)
		errorPageClean2 := cleanResponse(string(errorPage), randomHostname2)
		if errorPageClean != errorPageClean2 {
			log.Printf("[%s] Non-existing pages have different responses!", checkRange.Base)
		}
	}

	cachedResults := NewCache()
	for _, prefix := range checkRange.Prefixes {

		hostname := prefix + "." + checkRange.Base
		cachedDomain, err := cachedResults.FetchCachedResults(hostname, checkRange.Base)
		if err == nil && !noCache && time.Since(cachedDomain.Updated).Hours() < 48 {
			// log.Printf("Using cached data for %s", hostname)
			if len(cachedDomain.Address) > 0 && cachedDomain.PageBody {
				validRange.Prefixes = append(validRange.Prefixes, prefix)
			}
			continue
		}
		domainData := &CachedDomain{
			Updated:  time.Now(),
			PageBody: false,
			Address:  []string{},
		}
		address, err := net.LookupHost(hostname)
		if err == nil && len(address) > 0 {
			domainData.Address = address
			resp, err := http.Get(fmt.Sprintf("http://%s/", hostname))
			if err == nil {
				defer resp.Body.Close()
				testPage, _ := ioutil.ReadAll(resp.Body)
				cleanBody := cleanResponse(string(testPage), hostname)
				if cleanBody != errorPageClean {
					domainData.PageBody = true
					validRange.Prefixes = append(validRange.Prefixes, prefix)
				}
			} else {
				log.Printf("[%s] Could not access example subdomain page", hostname)
			}
		}
		cachedResults.UpdateCache(hostname, checkRange.Base, *domainData)
	}

	return validRange
}
