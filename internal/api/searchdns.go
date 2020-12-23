package api

import (
	"context"
	"fmt"
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

func parseCount(count string) int64 {
	records := strings.Fields(count)
	pageString := strings.TrimSuffix(records[len(records)-1], ")")
	pageNumber, err := strconv.ParseInt(pageString, 10, 0)
	if err != nil {
		log.Fatal("Could not parse page number")
	}

	return pageNumber
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

func SearchDNSQuery(domain string, position string) []string {

	log.Println("Querying SearchDNS for " + domain + " at position " + position)
	count, domains := browserFetch(domain, position, "", 0)

	pageCount := parseCount(count)
	subdomains, last := parseDomains(domains)

	log.Println("Page count: " + fmt.Sprint(pageCount))
	newSubdomains := []string{}
	for i := 1; int64(i) < pageCount; i++ {
		log.Print("Processing page " + fmt.Sprint(i) + "\r")
		_, domains = browserFetch(domain, position, last, len(subdomains)+1)
		newSubdomains, last = parseDomains(domains)

		if i%5 == 0 {
			log.Print("Sleeping...")
			time.Sleep(60 * time.Second)
		}
		subdomains = append(subdomains, newSubdomains...)
	}

	log.Println("Found " + fmt.Sprint(len(subdomains)) + " subdomains")
	return subdomains
}
