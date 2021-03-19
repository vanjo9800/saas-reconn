package checks

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"saasreconn/pkg/cache"

	"github.com/chromedp/chromedp"
)

var cacheWriteLock sync.Mutex

const maximumFailedAttempts = 15
const requestTimeout = 20 * time.Second
const requestBackOff = 200 * time.Millisecond
const parallelRequests = 5

var requestBurstLimiter chan bool = make(chan bool, parallelRequests)

func cleanBase(base string) string {
	base = strings.ReplaceAll(base, "/", "_")
	return base
}

func cleanResponse(responseBody string, hostname string, base string) string {
	cleanBody := responseBody

	// Remove the hostname
	reg := regexp.MustCompile(`\Q` + hostname + `\E`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	// Remove base URL in Okta response
	if strings.HasPrefix(base, "okta.com") {
		reg = regexp.MustCompile(`baseUrl\s=\s'.*?'`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
		reg = regexp.MustCompile(`<script>var w=window;if.*?clientip:.*?</script>`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
	}

	// Remove ID comment in Slack response
	if strings.HasPrefix(base, "slack.com") {
		reg = regexp.MustCompile(`<!--\sslack-www.*? -->`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
	}

	// Remove ID's in OneLogin response
	if strings.HasPrefix(base, "onelogin.com") {
		reg = regexp.MustCompile(`NREUM.info={.*?}|value="[a-zA-Z0-9/=+]+"`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
	}

	// Remove requestToken in Box response
	if strings.HasPrefix(base, "box.com") {
		reg = regexp.MustCompile(`requestToken\s=\s'[a-zA-Z0-9]+'`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
		reg = regexp.MustCompile(`value="[0-9a-zA-Z]+"`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
	}

	// Remove CDN links from Microsoft websites
	if strings.HasPrefix(base, "outlook") {
		reg = regexp.MustCompile(`[a-z]+cdn[.]ms(ft)?auth[.]net`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
		reg = regexp.MustCompile(`"hash":"[a-zA-Z0-9]+"`)
		cleanBody = reg.ReplaceAllString(cleanBody, "")
		// reg = regexp.MustCompile(`Config=\{.*?\};`)
		// cleanBody = reg.ReplaceAllString(cleanBody, "")
	}

	return cleanBody
}

func isInvalidTextResponse(responseBody string, hostname string, base string) bool {

	reg := regexp.MustCompile("")

	// There has been a glitch... - Slack error
	if strings.HasPrefix(base, "slack.com") {
		reg = regexp.MustCompile(`There has been a glitch...`)
		if reg.Match([]byte(responseBody)) {
			return true
		}
	}

	// Organisation logo for Okta
	if strings.HasPrefix(base, "okta.com") {
		reg = regexp.MustCompile("alt=\"Okta\"")
		if reg.Match([]byte(responseBody)) {
			return true
		}
	}

	// Default error page in Atlassian
	if strings.HasPrefix(base, "atlassian.net") {
		reg = regexp.MustCompile(`Atlassian Cloud Notifications - Page Unavailable`)
		if reg.Match([]byte(responseBody)) {
			return true
		}
	}

	// Default error page in Atlassian
	if strings.HasPrefix(base, "mailchimpsites.com") {
		reg = regexp.MustCompile(`We can't find that page`)
		if reg.Match([]byte(responseBody)) {
			return true
		}
	}

	// GitHub not found template
	if strings.HasPrefix(base, "github.com") {
		reg = regexp.MustCompile(`not-found-search`)
		if reg.Match([]byte(responseBody)) {
			return true
		}
	}

	return false
}

func httpSyncRequest(url string, verbosity int) (cleanBody string) {
	responseBody := make(chan string, 1)
	time.Sleep(requestBackOff)
	requestBurstLimiter <- true
	defer func() {
		<-requestBurstLimiter
	}()

	httpAsyncRequest(url, verbosity, responseBody)
	return <-responseBody
}

func httpAsyncRequest(url string, verbosity int, cleanBody chan<- string) {
	go func() {
		transportParameters := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Timeout:   requestTimeout,
			Transport: transportParameters,
		}
		resp, httpErr := client.Get(url)
		if httpErr != nil {
			ioTimeoutMatch, err := regexp.MatchString(`Timeout exceeded`, httpErr.Error())
			if err == nil && ioTimeoutMatch {
				failedAttempts := 0
				for {
					time.Sleep(time.Duration(math.Exp2(float64(failedAttempts-1))) * time.Millisecond)
					resp, err = client.Get(url)
					if err == nil {
						break
					}
					ioTimeoutMatch, err = regexp.MatchString(`Timeout exceeded`, err.Error())
					if err == nil && ioTimeoutMatch {
						if failedAttempts == maximumFailedAttempts {
							log.Printf("[%s] Exceeded back-off attempts, reporting timeout", url)
							cleanBody <- ""
							return
						}
						failedAttempts++
						log.Printf("[%s] Increased failed attempts %d", url, failedAttempts)
					}
				}
			} else {
				if verbosity >= 4 {
					noConnectionMatch, err := regexp.MatchString(`no such host|connection refused`, httpErr.Error())
					if err == nil && !noConnectionMatch {
						log.Printf("Could not access page %s: %s", url, httpErr)
					}
				}
				cleanBody <- ""
				return
			}
		}
		defer resp.Body.Close()
		pageBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if verbosity >= 4 {
				log.Printf("Could not extract page body %s: %s", url, err)
			}
			cleanBody <- ""
			return
		}
		if resp.StatusCode >= 400 {
			if verbosity >= 5 {
				log.Printf("Response for %s has an error code %d, invalidating", url, resp.StatusCode)
			}
			cleanBody <- ""
			return
		}
		cleanBody <- string(pageBody)
	}()
}

func randomPageBody(addressBase AddressBase, verbosity int) (cleanBody string) {

	randomClient1 := "saas-reconn1"
	randomClient2 := "saas-reconn2"

	errorPageClean1 := cleanResponse(httpSyncRequest(addressBase.GetUrl(randomClient1), verbosity), randomClient1, addressBase.GetBase())
	errorPageClean2 := cleanResponse(httpSyncRequest(addressBase.GetUrl(randomClient2), verbosity), randomClient2, addressBase.GetBase())

	if errorPageClean1 != errorPageClean2 && verbosity >= 2 {
		log.Printf("[%s] HINT: Non-existing pages have different responses!", addressBase.GetBase())
	}

	return errorPageClean1
}

func headlessChromeReq(url string, keyElement string, verbosity int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	data := ""
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Text(keyElement, &data, chromedp.NodeVisible, chromedp.ByQuery),
	)
	if err != nil {
		if verbosity >= 2 {
			log.Printf("[%s] Headless Chrome request error %s", url, err)
		}
		return false
	}

	return true
}

func (checkRange SubdomainRange) Validate(noCache bool, verbosity int) (validRange SubdomainRange) {
	validRange.Base = checkRange.Base

	headlessFlag := ""
	if strings.HasPrefix(checkRange.Base.GetBase(), "outlook") {
		headlessFlag = ".banner-logo"
	}

	errorPageClean := randomPageBody(checkRange.Base, verbosity)

	validPrefixes := make(chan string, 5)
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

			if reflect.TypeOf(checkRange.Base).Name() == "SubdomainBase" {
				url, err := url.Parse(checkRange.Base.GetUrl(prefix))
				address, err := net.LookupHost(url.Hostname())
				if err != nil || len(address) == 0 {
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
				}
				return
			}
			cleanBody := cleanResponse(httpSyncRequest(checkRange.Base.GetUrl(prefix), verbosity), prefix, checkRange.Base.GetBase())
			if cleanBody == "" {
				if strings.HasSuffix(checkRange.Base.GetBase(), "webex.com") {
					log.Printf("Empty body for %s", prefix)
				}
				if verbosity >= 5 {
					log.Printf("[%s] Could not access subdomain page", checkRange.Base.GetUrl(prefix))
				}
				return
			}
			if cleanBody != errorPageClean {
				// url, _ := url.Parse(checkRange.Base.GetUrl(prefix))
				if !isInvalidTextResponse(cleanBody, prefix, checkRange.Base.GetBase()) {
					// if strings.HasPrefix(url.Hostname(), "outlook") {
					// 	err = ioutil.WriteFile("temp/"+prefix+"."+url.Hostname()+".json", []byte(cleanBody), 0755)
					// 	err = ioutil.WriteFile("temp/"+url.Hostname()+".json", []byte(errorPageClean), 0755)
					// }
					domainData.PageBody = true
					validPrefixes <- prefix
				}
			} else {

			}
		}(prefix, checkRange, headlessFlag, errorPageClean, &prefixWorkgroup)
	}

	go func(prefixWorkgroup *sync.WaitGroup) {
		prefixWorkgroup.Wait()
		close(validPrefixes)
	}(&prefixWorkgroup)

	for {
		prefix, more := <-validPrefixes
		if more {
			validRange.Prefixes = append(validRange.Prefixes, prefix)
		} else {
			break
		}
	}

	return validRange
}
