package api

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

func browserFetch(domain string, position string, last string, from int) (count string, domains string) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	url := "https://searchdns.netcraft.com/?restriction=site+" + position + "+with&"
	if from != 0 {
		url += "from=" + strconv.Itoa(from) + "&last=" + last + "&"
	}
	url += "host=" + domain + "&position=limited"
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Text(".results-table", &domains, chromedp.NodeVisible, chromedp.ByQuery),
		chromedp.Text(".banner__container--text > h2", &count, chromedp.NodeVisible, chromedp.ByQuery),
	)
	if err != nil {
		log.Println(err)
		return count, domains
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

	log.Printf("[%s] Querying SearchDNS position %s", domain, position)
	start := time.Now()
	count, domains := browserFetch(domain, position, "", 0)

	pageCount, err := parseCount(count)
	if err != nil {
		log.Printf("[%s] Could not parse page number", domain)
		return subdomains
	}
	subdomains, last := parseDomains(domains)

	log.Printf("[%s] Page count: %d", domain, pageCount)
	newSubdomains := []string{}
	for i := 1; int64(i) < pageCount; i++ {
		log.Printf("[%s] Processing page %d\r", domain, i)
		_, domains = browserFetch(domain, position, last, len(subdomains)+1)
		newSubdomains, last = parseDomains(domains)

		if i%5 == 0 {
			log.Printf("[%s] Sleeping...", domain)
			time.Sleep(300 * time.Second)
		}
		subdomains = append(subdomains, newSubdomains...)
	}

	elapsed := time.Since(start)
	log.Printf("[%s] Found %d subdomains in %s", domain, len(subdomains), elapsed)
	return subdomains
}
