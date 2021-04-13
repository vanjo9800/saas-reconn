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

	"saasreconn/internal/cache"
	"saasreconn/internal/tools"
)

// Config is a class for configuration of the zone-walking module
type Config struct {
	Cache         bool
	CacheLifetime float64
	Parallel      int
	Verbose       int
}

var cacheWriteLock sync.Mutex

func randomPageBody(addressBase AddressBase, verbosity int) (cleanBody string) {

	randomClient1 := "saas-reconn1"
	randomClient2 := "saas-reconn2"

	randomSubdomainURL, urlErr := url.Parse(addressBase.GetUrl(randomClient1))
	address, dnsErr := net.LookupHost(randomSubdomainURL.Hostname())
	if urlErr != nil || dnsErr != nil || len(address) == 0 {
		return ""
	}

	errorPageClean1 := tools.CleanResponse(tools.HttpSyncRequest(addressBase.GetUrl(randomClient1), verbosity), randomClient1, addressBase.GetBase())
	errorPageClean2 := tools.CleanResponse(tools.HttpSyncRequest(addressBase.GetUrl(randomClient2), verbosity), randomClient2, addressBase.GetBase())

	if errorPageClean1 != "" && errorPageClean2 != "" && errorPageClean1 != errorPageClean2 && verbosity >= 2 {
		ioutil.WriteFile("temp/"+addressBase.GetBase()+"saasreconn1.json", []byte(errorPageClean1), 0755)
		ioutil.WriteFile("temp/"+addressBase.GetBase()+"saasreconn2.json", []byte(errorPageClean2), 0755)
		log.Printf("[%s] HINT: Non-existing pages have different responses!", addressBase.GetBase())
	}

	return errorPageClean1
}

func (checkRange SubdomainRange) Validate(config Config) (validRange SubdomainRange, invalidRange SubdomainRange) {
	validRange.Base = checkRange.Base
	invalidRange.Base = checkRange.Base

	headlessFlag := ""
	if strings.HasPrefix(checkRange.Base.GetBase(), "outlook") {
		headlessFlag = ".banner-logo"
	}

	errorPageClean := randomPageBody(checkRange.Base, config.Verbose)

	validPrefixes := make(chan string, config.Parallel)
	invalidPrefixes := make(chan string, config.Parallel)

	cachedResults := cache.NewCache()

	var prefixWorkgroup sync.WaitGroup
	for _, prefix := range checkRange.Prefixes {
		prefixWorkgroup.Add(1)
		go func(config Config, prefix string, checkRange SubdomainRange, headlessFlag string, errorPageClean string, prefixWorkgroup *sync.WaitGroup) {
			defer prefixWorkgroup.Done()
			cachedDomain, err := cachedResults.FetchCachedDomainCheckResults(prefix, tools.CleanBase(checkRange.Base.GetBase()))
			if err == nil && config.Cache && time.Since(cachedDomain.Updated).Hours() < config.CacheLifetime {
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
				cachedResults.UpdateCachedDomainCheckData(prefix, tools.CleanBase(checkRange.Base.GetBase()), *domainData)
			}()

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
				isValid := tools.HeadlessChromeRequest(checkRange.Base.GetUrl(prefix), headlessFlag, config.Verbose)
				if isValid {
					domainData.PageBody = true
					validPrefixes <- prefix
				} else {
					invalidPrefixes <- prefix
				}
				return
			}
			cleanBody := tools.CleanResponse(tools.HttpSyncRequest(checkRange.Base.GetUrl(prefix), config.Verbose), prefix, checkRange.Base.GetBase())
			if cleanBody == "" {
				if config.Verbose >= 5 {
					log.Printf("[%s] Could not access subdomain page", checkRange.Base.GetUrl(prefix))
				}
				invalidPrefixes <- prefix
				return
			}
			if cleanBody != errorPageClean {
				if !tools.IsInvalidTextResponse(cleanBody, checkRange.Base.GetBase()) {
					domainData.PageBody = true
					validPrefixes <- prefix
				} else {
					invalidPrefixes <- prefix
				}
			} else {
				invalidPrefixes <- prefix
			}
		}(config, prefix, checkRange, headlessFlag, errorPageClean, &prefixWorkgroup)
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
