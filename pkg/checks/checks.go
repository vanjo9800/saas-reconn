package checks

import (
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"saasreconn/pkg/cache"
)

var cacheWriteLock sync.Mutex

func randomPageBody(addressBase AddressBase, verbosity int) (cleanBody string) {

	randomClient1 := "saas-reconn1"
	randomClient2 := "saas-reconn2"

	randomSubdomainURL, urlErr := url.Parse(addressBase.GetUrl(randomClient1))
	address, dnsErr := net.LookupHost(randomSubdomainURL.Hostname())
	if urlErr != nil || dnsErr != nil || len(address) == 0 {
		return ""
	}

	errorPageClean1 := cleanResponse(httpSyncRequest(addressBase.GetUrl(randomClient1), verbosity), randomClient1, addressBase.GetBase())
	errorPageClean2 := cleanResponse(httpSyncRequest(addressBase.GetUrl(randomClient2), verbosity), randomClient2, addressBase.GetBase())

	if errorPageClean1 != "" && errorPageClean2 != "" && errorPageClean1 != errorPageClean2 && verbosity >= 2 {
		ioutil.WriteFile("temp/"+addressBase.GetBase()+"saasreconn1.json", []byte(errorPageClean1), 0755)
		ioutil.WriteFile("temp/"+addressBase.GetBase()+"saasreconn2.json", []byte(errorPageClean2), 0755)
		log.Printf("[%s] HINT: Non-existing pages have different responses!", addressBase.GetBase())
	}

	return errorPageClean1
}

func (checkRange SubdomainRange) Validate(noCache bool, verbosity int) (validRange SubdomainRange, invalidRange SubdomainRange) {
	validRange.Base = checkRange.Base
	invalidRange.Base = checkRange.Base

	headlessFlag := ""
	if strings.HasPrefix(checkRange.Base.GetBase(), "outlook") {
		headlessFlag = ".banner-logo"
	}

	errorPageClean := randomPageBody(checkRange.Base, verbosity)

	validPrefixes := make(chan string, 5)
	invalidPrefixes := make(chan string, 5)

	cachedResults := cache.NewCache()

	var prefixWorkgroup sync.WaitGroup
	for _, prefix := range checkRange.Prefixes {
		prefixWorkgroup.Add(1)
		go func(prefix string, checkRange SubdomainRange, headlessFlag string, errorPageClean string, prefixWorkgroup *sync.WaitGroup) {
			defer prefixWorkgroup.Done()
			cachedDomain, err := cachedResults.FetchCachedDomainCheckResults(prefix, cleanBase(checkRange.Base.GetBase()))
			if err == nil && !noCache && time.Since(cachedDomain.Updated).Hours() < 48 {
				if len(cachedDomain.Address) > 0 && cachedDomain.PageBody {
					validPrefixes <- prefix
				} else {
					invalidPrefixes <- prefix
				}
				return
			}

			domainData := &cache.CachedDomainCheck{
				Updated:  time.Now(),
				PageBody: false,
				Address:  []string{},
			}

			defer func() {
				cachedResults.UpdateCachedDomainCheckData(prefix, cleanBase(checkRange.Base.GetBase()), *domainData)
			}()

			// fmt.Printf("Checking %s\n", checkRange.Base.GetUrl(prefix))
			if reflect.TypeOf(checkRange.Base).Name() == "SubdomainBase" {
				url, err := url.Parse(checkRange.Base.GetUrl(prefix))
				address, err := net.LookupHost(url.Hostname())
				if err != nil || len(address) == 0 {
					invalidPrefixes <- prefix
					return
				}
				domainData.Address = address
			}

			if len(domainData.Address) == 0 {
				domainData.Address = []string{"1"}
			}
			if len(headlessFlag) > 0 {
				isValid := headlessChromeReq(checkRange.Base.GetUrl(prefix), headlessFlag, verbosity)
				if isValid {
					domainData.PageBody = true
					validPrefixes <- prefix
				} else {
					invalidPrefixes <- prefix
				}
				return
			}
			cleanBody := cleanResponse(httpSyncRequest(checkRange.Base.GetUrl(prefix), verbosity), prefix, checkRange.Base.GetBase())
			if cleanBody == "" {
				if verbosity >= 5 {
					log.Printf("[%s] Could not access subdomain page", checkRange.Base.GetUrl(prefix))
				}
				invalidPrefixes <- prefix
				return
			}
			if cleanBody != errorPageClean {
				// url, _ := url.Parse(checkRange.Base.GetUrl(prefix))
				if !isInvalidTextResponse(cleanBody, checkRange.Base.GetBase()) {
					// if strings.HasPrefix(url.Hostname(), "outlook") {
					if strings.HasSuffix(checkRange.Base.GetBase(), "box.com") {
						err = ioutil.WriteFile("temp/"+prefix+"."+"box.com.json", []byte(cleanBody), 0755)
					}
					// 	err = ioutil.WriteFile("temp/"+url.Hostname()+".json", []byte(errorPageClean), 0755)
					// }
					domainData.PageBody = true
					validPrefixes <- prefix
				} else {
					invalidPrefixes <- prefix
				}
			} else {
				invalidPrefixes <- prefix
			}
		}(prefix, checkRange, headlessFlag, errorPageClean, &prefixWorkgroup)
	}

	var resultsParsers sync.WaitGroup
	resultsParsers.Add(1)
	go func(resultsParsers *sync.WaitGroup) {
		defer resultsParsers.Done()
		for {
			prefix, more := <-validPrefixes
			if !more {
				break
			}
			validRange.Prefixes = append(validRange.Prefixes, prefix)
		}
	}(&resultsParsers)
	resultsParsers.Add(1)
	go func(resultsParsers *sync.WaitGroup) {
		defer resultsParsers.Done()
		for {
			prefix, more := <-invalidPrefixes
			if !more {
				break
			}
			invalidRange.Prefixes = append(invalidRange.Prefixes, prefix)
		}
	}(&resultsParsers)

	prefixWorkgroup.Wait()
	close(validPrefixes)
	close(invalidPrefixes)
	resultsParsers.Wait()

	return validRange, invalidRange
}
