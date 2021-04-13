package tools

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"regexp"
	"time"

	"github.com/chromedp/chromedp"
)

const maximumFailedAttempts = 5
const requestTimeout = 10 * time.Second

func HttpSyncRequest(url string, verbosity int) string {
	responseBody := make(chan string, 1)

	HttpAsyncRequest(url, verbosity, responseBody)
	return <-responseBody
}

func HttpAsyncRequest(url string, verbosity int, responseBody chan<- string) {
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
					time.Sleep(time.Duration(math.Exp2(float64(failedAttempts-1))) * time.Millisecond * 10)
					resp, err = client.Get(url)
					if err == nil {
						break
					}
					ioTimeoutMatch, err = regexp.MatchString(`Timeout exceeded`, err.Error())
					if err == nil && ioTimeoutMatch {
						if failedAttempts == maximumFailedAttempts {
							log.Printf("[%s] Exceeded back-off attempts, reporting timeout", url)
							responseBody <- ""
							return
						}
						failedAttempts++
					}
				}
			} else {
				if verbosity >= 4 {
					noConnectionMatch, err := regexp.MatchString(`no such host|connection refused`, httpErr.Error())
					if err == nil && !noConnectionMatch {
						log.Printf("Could not access page %s: %s", url, httpErr)
					}
				}
				responseBody <- ""
				return
			}
		}
		defer resp.Body.Close()
		pageBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if verbosity >= 4 {
				log.Printf("Could not extract page body %s: %s", url, err)
			}
			responseBody <- ""
			return
		}
		if resp.StatusCode >= 400 {
			if verbosity >= 5 {
				log.Printf("Response for %s has an error code %d, invalidating", url, resp.StatusCode)
			}
			responseBody <- ""
			return
		}
		pageBodyString := string(pageBody) + resp.Request.URL.Host
		responseBody <- pageBodyString
	}()
}

func HeadlessChromeRequest(url string, keyElement string, verbosity int) bool {
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
