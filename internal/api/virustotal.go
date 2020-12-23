package api

import (
	"context"
	"log"

	"github.com/chromedp/chromedp"
)

func browserAccess(domain string) (domains string) {

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var outerBefore string
	url := "https://www.virustotal.com/gui/domain/" + domain + "/relations"
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		// chromedp.Text(".table", &domains, chromedp.NodeVisible, chromedp.ByQuery),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.OuterHTML("body", &outerBefore, chromedp.ByQuery),
		// chromedp.Text(".banner__container--text > h2", &count, chromedp.NodeVisible, chromedp.ByQuery),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(outerBefore)

	return domains

}

func VirusTotalQuery(domain string) {

	domains := browserAccess(domain)

	log.Println(domains)
}
