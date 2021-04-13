package db

import (
	"log"
	"testing"
)

var sampleProviderData ProviderData = ProviderData{
	Provider: "Sample",
	Subdomains: map[string][]Subdomain{
		"example.com": []Subdomain{
			Subdomain{
				Name:         "test.example.com",
				Confidence:   50,
				DiscoveredBy: []string{"Testing suite"},
			},
			Subdomain{
				Name:         "test123.example.com",
				Confidence:   50,
				DiscoveredBy: []string{"Testing suite"},
			},
		},
	},
}

func TestQuery(t *testing.T) {
	expectedResult := ProviderData{
		Provider: "Sample",
		Subdomains: map[string][]Subdomain{
			"example.com": []Subdomain{
				Subdomain{
					Name:         "test.example.com",
					Confidence:   50,
					DiscoveredBy: []string{"Testing suite"},
				},
			},
		},
	}
	resultData := sampleProviderData.query("test[.]")
	resultData.Collected = expectedResult.Collected
	verdict := resultData.IsEqual(&expectedResult)
	if !verdict {
		log.Printf("Expected: %s", expectedResult.ToString())
		log.Printf("Got : %s", resultData.ToString())
		t.Errorf("[ProviderData.query()] query unsuccessful")
	}
}

func TestUpdateDomainEntries(t *testing.T) {
	testingProviderData := sampleProviderData
	testingProviderData.updateDomainEntries("example.com", []Subdomain{
		Subdomain{
			Name:         "test456.example.com",
			Confidence:   50,
			DiscoveredBy: []string{"Testing suite"},
		},
		Subdomain{
			Name:         "test123.example.com",
			Confidence:   60,
			DiscoveredBy: []string{"Testing suite"},
		},
	})
	expectedResult := ProviderData{
		Provider: "Sample",
		Subdomains: map[string][]Subdomain{
			"example.com": []Subdomain{
				Subdomain{
					Name:         "test123.example.com",
					Confidence:   60,
					DiscoveredBy: []string{"Testing suite"},
				},
				Subdomain{
					Name:         "test.example.com",
					Confidence:   50,
					DiscoveredBy: []string{"Testing suite"},
				},
				Subdomain{
					Name:         "test456.example.com",
					Confidence:   50,
					DiscoveredBy: []string{"Testing suite"},
				},
			},
		},
	}
	verdict := testingProviderData.IsEqual(&expectedResult)
	if !verdict {
		log.Printf("Expected: %s", expectedResult.ToString())
		log.Printf("Got : %s", testingProviderData.ToString())
		t.Errorf("[ProviderData.updateDomainEntries()] update unsuccessful")
	}
}
