package api

import (
	"context"
	"fmt"
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

func browserFetch(ctx context.Context, domain string, position string, last string, from int, verbosity int) (count string, domains string) {

	url := "https://searchdns.netcraft.com/?restriction=site+" + position + "+with&"
	if from != 0 {
		url += "from=" + strconv.Itoa(from) + "&last=" + last + "&"
	}
	url += "host=" + domain + "&position=limited"
	for {
		if verbosity >= 4 {
			log.Printf("[SearchDNS] Querying url `%s`", url)
		}

		// Add fetchTimeout to context
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		ctx, cancel = chromedp.NewContext(ctx)
		defer cancel()

		err := chromedp.Run(ctx,
			chromedp.Navigate(url),
			chromedp.Text(".results-table", &domains, chromedp.NodeVisible, chromedp.ByQuery),
			chromedp.Text(".banner__container--text > h2", &count, chromedp.NodeVisible, chromedp.ByQuery),
		)
		if err == nil {
			failedQueries = 0
			break
		}
		failedQueries = int(math.Min(10, float64(failedQueries)+1))
		if verbosity >= 3 {
			log.Printf("[SearchDNS] Request for `%s` gave error %s, backing off\n failed attempts so far %d", url, err, failedQueries)
		}
		time.Sleep(time.Duration(math.Exp2(float64(failedQueries-1))) * time.Second)
	}

	return count, domains

}

func parseCount(count string) int64 {
	records := strings.Fields(count)
	resultsCountString := records[0]
	if records[0] == "First" {
		// First 500 results
		resultsCountString = records[1]
	}
	resultsCount, err := strconv.ParseInt(resultsCountString, 10, 0)
	if err != nil {
		log.Printf("Could not parse page number from %s: %s", count, err)
		return 0
	}

	return (resultsCount / 20) + 1
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

func SearchDNSQuery(domain string, position string, verbosity int) (subdomains []string) {

	if verbosity >= 2 {
		log.Printf("[SearchDNS] Querying SearchDNS with domain `%s` at position `%s`", domain, position)
	}
	start := time.Now()

	// Create Chrome instance
	chromeCtx, cancel := chromedp.NewContext(context.Background(), chromedp.WithLogf(log.Printf))
	defer cancel()

	// Start Chrome
	if err := chromedp.Run(chromeCtx); err != nil {
		log.Printf("[%s] Unable to start Chrome: %s", domain, err)
		return subdomains
	}

	count, domains := browserFetch(chromeCtx, domain, position, "", 0, verbosity)

	pageCount := parseCount(count)
	subdomains, last := parseDomains(domains)

	if verbosity >= 3 {
		log.Printf("[SearchDNS] Page count: %d", pageCount)
	}
	for i := 1; int64(i) < pageCount; i++ {
		if verbosity >= 4 {
			fmt.Printf("\r[SearchDNS] Processing page %d", i)
		}
		_, domains = browserFetch(chromeCtx, domain, position, last, len(subdomains)+1, verbosity)
		time.Sleep(fetchRate)

		var newSubdomains []string
		newSubdomains, last = parseDomains(domains)

		subdomains = append(subdomains, newSubdomains...)
	}
	if verbosity >= 4 {
		fmt.Println()
	}

	elapsed := time.Since(start)
	if verbosity >= 2 {
		log.Printf("[SearchDNS] Found %d subdomains in %s", len(subdomains), elapsed)
	}
	return subdomains
}
