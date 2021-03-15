package api

import (
	"context"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

const fetchTimeout = 10.0 * time.Second
const fetchRate = 4.0 * time.Second

var failedQueries = 0

func browserFetch(ctx context.Context, domain string, position string, last string, from int) (count string, domains string) {

	url := "https://searchdns.netcraft.com/?restriction=site+" + position + "+with&"
	if from != 0 {
		url += "from=" + strconv.Itoa(from) + "&last=" + last + "&"
	}
	url += "host=" + domain + "&position=limited"
	for {
		log.Printf("[%s] Querying url %s", domain, url)

		// Add fetchTimeout to context
		ctx, _ = context.WithTimeout(ctx, fetchTimeout)
		ctx, _ = chromedp.NewContext(ctx)

		err := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.Text(".results-table", &domains, chromedp.NodeVisible, chromedp.ByQuery),
			chromedp.Text(".banner__container--text > h2", &count, chromedp.NodeVisible, chromedp.ByQuery),
		)
		if err == nil {
			failedQueries = 0
			break
		}
		log.Printf("[%s] Gave error %s\n failed attempts so far %d", domain, err, failedQueries)
		failedQueries = int(math.Min(10, float64(failedQueries)+1))
		log.Printf("Sleeping for %s", time.Duration(math.Exp2(float64(failedQueries-1)))*time.Second)
		time.Sleep(time.Duration(math.Exp2(float64(failedQueries-1))) * time.Second)
	}

	return count, domains

}

func parseCount(count string) (pageNumber int64, err error) {
	records := strings.Fields(count)
	pageString := strings.TrimSuffix(records[len(records)-1], ")")

	return strconv.ParseInt(pageString, 10, 0)
}

func parseDomains(domains string) (subdomains []string, last string) {

	records := strings.Split(domains, "\n")
	for _, subdomain := range records[1:] {
		details := strings.Split(subdomain, "\t")
		last = details[1]
		subdomains = append(subdomains, details[1])
	}

	return subdomains, last
}

func SearchDNSQuery(domain string, position string) (subdomains []string) {

	log.Printf("[%s] Querying SearchDNS with domain at position `%s`", domain, position)
	start := time.Now()

	// Create Chrome instance
	chromeCtx, cancel := chromedp.NewContext(context.Background(), chromedp.WithLogf(log.Printf))
	defer cancel()

	// Start Chrome
	if err := chromedp.Run(chromeCtx); err != nil {
		log.Printf("[%s] Unable to start Chrome: %s", domain, err)
		return subdomains
	}

	count, domains := browserFetch(chromeCtx, domain, position, "", 0)

	pageCount, err := parseCount(count)
	if err != nil {
		log.Printf("[%s] Could not parse page number", domain)
		return subdomains
	}
	subdomains, last := parseDomains(domains)

	log.Printf("[%s] Page count: %d", domain, pageCount)
	for i := 1; int64(i) < pageCount; i++ {
		log.Printf("[%s] Processing page %d\r", domain, i)
		_, domains = browserFetch(chromeCtx, domain, position, last, len(subdomains)+1)
		time.Sleep(fetchRate)

		var newSubdomains []string
		newSubdomains, last = parseDomains(domains)

		// if i%5 == 0 {
		// 	log.Printf("[%s] Sleeping...", domain)
		// 	time.Sleep(3 * time.Second)
		// }
		subdomains = append(subdomains, newSubdomains...)
	}

	elapsed := time.Since(start)
	log.Printf("[%s] Found %d subdomains in %s", domain, len(subdomains), elapsed)
	return subdomains
}
