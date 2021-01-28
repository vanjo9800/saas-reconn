package checks

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"saasreconn/pkg/cache"

	"github.com/chromedp/chromedp"
)

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

func randomPageBody(addressBase AddressBase) (cleanBody string) {

	randomClient1 := "hdmmndjzsj"
	randomClient2 := "wbuiiionia"

	errorPageClean := ""
	resp, err := http.Get(addressBase.GetUrl(randomClient1))
	if err != nil {
		log.Printf("[%s] Could not access random subdomain page, domain must be existing", addressBase.GetBase())
		return ""
	}

	defer resp.Body.Close()
	errorPage, _ := ioutil.ReadAll(resp.Body)
	errorPageClean = cleanResponse(string(errorPage), randomClient1, addressBase.GetBase())

	resp, _ = http.Get(addressBase.GetUrl(randomClient2))
	defer resp.Body.Close()
	errorPage, _ = ioutil.ReadAll(resp.Body)
	errorPageClean2 := cleanResponse(string(errorPage), randomClient2, addressBase.GetBase())
	if errorPageClean != errorPageClean2 {
		log.Printf("[%s] Non-existing pages have different responses!", addressBase.GetBase())
	}

	return errorPageClean
}

func headlessChromeReq(url string, keyElement string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	data := ""
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Text(keyElement, &data, chromedp.NodeVisible, chromedp.ByQuery),
	)
	if err != nil {
		log.Printf("[%s] %s", url, err)
		return false
	}

	return true
}

func (checkRange SubdomainRange) Validate(noCache bool) (validRange SubdomainRange) {
	validRange.Base = checkRange.Base

	headlessFlag := ""
	if strings.HasPrefix(checkRange.Base.GetBase(), "outlook") {
		headlessFlag = ".banner-logo"
	}

	errorPageClean := randomPageBody(checkRange.Base)

	cachedResults := cache.NewCache()
	for _, prefix := range checkRange.Prefixes {

		cachedDomain, err := cachedResults.FetchCachedDomainCheckResults(prefix, checkRange.Base.GetBase())
		if err == nil && !noCache && time.Since(cachedDomain.Updated).Hours() < 48 {
			// log.Printf("Using cached data for %s", hostname)
			if len(cachedDomain.Address) > 0 && cachedDomain.PageBody {
				validRange.Prefixes = append(validRange.Prefixes, prefix)
			}
			continue
		}

		domainData := &cache.CachedDomainCheck{
			Updated:  time.Now(),
			PageBody: false,
			Address:  []string{},
		}

		lookupFlag := true
		if reflect.TypeOf(checkRange.Base).Name() == "SubdomainBase" {
			url, err := url.Parse(checkRange.Base.GetUrl(prefix))
			address, err := net.LookupHost(url.Hostname())
			if err != nil || len(address) == 0 {
				lookupFlag = false
			}
			domainData.Address = address
		}

		if lookupFlag {
			if len(domainData.Address) == 0 {
				domainData.Address = []string{"1"}
			}
			if len(headlessFlag) > 0 {
				isValid := headlessChromeReq(checkRange.Base.GetUrl(prefix), headlessFlag)
				if isValid {
					domainData.PageBody = true
					validRange.Prefixes = append(validRange.Prefixes, prefix)
				}
			} else {
				resp, err := http.Get(checkRange.Base.GetUrl(prefix))
				if err == nil {
					defer resp.Body.Close()
					testPage, _ := ioutil.ReadAll(resp.Body)
					cleanBody := cleanResponse(string(testPage), prefix, checkRange.Base.GetBase())
					if resp.StatusCode < 400 && cleanBody != errorPageClean {
						url, _ := url.Parse(checkRange.Base.GetUrl(prefix))
						if !isInvalidTextResponse(cleanBody, prefix, checkRange.Base.GetBase()) {
							if strings.HasPrefix(url.Hostname(), "outlook") {
								err = ioutil.WriteFile("temp/"+prefix+"."+url.Hostname()+".json", []byte(cleanBody), 0755)
								err = ioutil.WriteFile("temp/"+url.Hostname()+".json", []byte(errorPageClean), 0755)
							}
							domainData.PageBody = true
							validRange.Prefixes = append(validRange.Prefixes, prefix)
						}
					}
				} else {
					log.Printf("[%s] Could not access example subdomain page", checkRange.Base.GetUrl(prefix))
				}
			}
		}
		cachedResults.UpdateCachedDomainCheckData(prefix, checkRange.Base.GetBase(), *domainData)
	}

	return validRange
}
