package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type VTDomain struct {
	Attributes map[string]interface{} `json:"attributes"`
	Id         string                 `json:"id"`
	Links      VTLinks                `json:"links"`
	Type       string                 `json:"type"`
}

type VTLinks struct {
	Next string `json:"next"`
	Self string `json:"self"`
}

type VTMeta struct {
	Count  int    `json:"count"`
	Cursor string `json:"cursor"`
}

type VTResponse struct {
	Domains []VTDomain `json:"data"`
	Links   VTLinks    `json:"links"`
	Meta    VTMeta     `json:"meta"`
}

const initialLink = "https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40"

func VirusTotalQuery(domain string, apikey string, verbosity int) (subdomains []string) {

	if verbosity >= 2 {
		log.Printf("[VirusTotal] Querying for `%s`", domain)
	}
	start := time.Now()

	if len(apikey) == 0 {
		log.Printf("[%s] No VirusTotal API key found", domain)
		return subdomains
	}

	client := &http.Client{}
	queryLink := fmt.Sprintf(initialLink, domain)

	for {
		if verbosity >= 4 {
			log.Printf("[VirusTotal] About to query `%s`", queryLink)
		}
		req, err := http.NewRequest("GET", queryLink, nil)
		req.Header.Add("x-apikey", apikey)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[%s] Could not connect to VirusTotal %s", domain, err)
			break
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		data := &VTResponse{}
		err = json.Unmarshal(body, &data)
		if err != nil {
			log.Printf("[%s] Invalid JSON response", domain)
			break
		}

		for _, domain := range data.Domains {
			subdomains = append(subdomains, domain.Id)
		}

		if data.Links.Next == "" {
			break
		}
		queryLink = data.Links.Next
	}

	elapsed := time.Since(start)
	if verbosity >= 2 {
		log.Printf("[VirusTotal] Found %d subdomains for `%s` in %s", len(subdomains), domain, elapsed)
	}
	return subdomains
}
