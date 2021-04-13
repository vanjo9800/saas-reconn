package api

import (
	"strings"
	"testing"
)

func TestParsePageCount(t *testing.T) {
	testInputs := []string{"12 results", "Sorry, no results were found.", "First 500 results <small>(showing 1 to 20)</small>"}
	testOutputs := []int64{1, 0, 26}

	for index, val := range testInputs {
		result := parsePageCount(val)
		if result != testOutputs[index] {
			t.Errorf("[SearchDNS] parsePageCount %s got %d, wanted %d", val, result, testOutputs[index])
		}
	}
}

func TestParseDomains(t *testing.T) {
	expectedSubdomainsResult := []string{"netcraft.slack.com", "netcraft.com"}
	expectedLastResult := "netcraft.com"

	subdomains, last := parseDomains(domainTestInput)

	if last != expectedLastResult {
		t.Errorf("[SearchDNS] parseDomains got last %s, expected %s", last, expectedLastResult)
	}
	if strings.Join(subdomains, ",") != strings.Join(expectedSubdomainsResult, ",") {
		t.Errorf("[SearchDNS] parseDomains got subdomains %s, expected %s", strings.Join(subdomains, ","), strings.Join(expectedSubdomainsResult, ","))
	}
}

var domainTestInput string = `Rank	Site	First seen	Netblock	OS	Site Report
2	netcraft.slack.com	Febuary 2014	Amazon.com, Inc.	unknown
3	netcraft.com	March 1996	DigitalOcean, LLC	Linux`
