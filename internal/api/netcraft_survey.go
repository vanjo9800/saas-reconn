package api

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
	"time"
)

func SurveyQuery(domain string) (subdomains []string) {

	log.Println("Querying Netcraft survey data for " + domain)
	start := time.Now()

	cmd := exec.Command("ssh", "creda", "pzcat /home/survey/zonefetch/zonefiles/all_hosts_list.gz | grep -P '[.]\\Q" + domain + "\\E$'")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	subdomains = strings.Split(out.String(), "\n")
	
	elapsed := time.Since(start)
	log.Printf("Found %d subdomains in %s", len(subdomains), elapsed)
	return subdomains
}
