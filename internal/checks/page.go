package checks

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func (checkRange SubdomainRange) UniquePage() (uniqueRange SubdomainRange) {

	resp, err := http.Get(fmt.Sprintf("http://hdmmndjzsj.%s/", checkRange.Base))
	if err != nil {
		log.Printf("[%s] Could not access random subdomain page, domain must be existing", checkRange.Base)
		return checkRange
	}
	defer resp.Body.Close()
	randomBody1, err := ioutil.ReadAll(resp.Body)
	resp, err = http.Get(fmt.Sprintf("http://wbuiiionia.%s/", checkRange.Base))
	defer resp.Body.Close()
	randomBody2, err := ioutil.ReadAll(resp.Body)
	if string(randomBody1) == string(randomBody2) {
		log.Printf("[%s] Non-existing pages have the same response", checkRange.Base)
	} else {
		log.Printf("[%s] Non-existing pages have different responses!", checkRange.Base)
	}
	uniqueRange.Base = checkRange.Base
	for _, prefix := range checkRange.Prefixes {
		resp, err := http.Get(fmt.Sprintf("http://%s.%s/", prefix, checkRange.Base))
		if err != nil {
			log.Printf("[%s] Could not access example subdomain page", checkRange.Base)
		}
		defer resp.Body.Close()
		testBody, err := ioutil.ReadAll(resp.Body)
		if string(testBody) != string(randomBody1) {
			uniqueRange.Prefixes = append(uniqueRange.Prefixes, prefix)
		}
	}

	return uniqueRange
}
