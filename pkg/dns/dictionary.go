package dns

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"saasreconn/pkg/db"
	"strings"
)

const amassWordlistName string = "resources/namelist.txt"

// BuildDictionary builds a dictionary channel for NSEC3 hash dictionary attack
func BuildDictionary(dictionary chan<- string) {
	addWordList(dictionary, amassWordlistName)
	addProviderData(dictionary)
	close(dictionary)
}

func addProviderData(dictionary chan<- string) {
	var providers []string

	providerDatabase := db.NewDatabase()
	providerDatabase.Initialise()

	err := filepath.Walk(providerDatabase.Root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			path = strings.TrimPrefix(path, providerDatabase.Root)
			path = strings.TrimSuffix(path, ".json")
			providers = append(providers, path)
		}
		return nil
	})
	if err != nil || len(providers) == 0 {
		log.Printf("Could not find any provider information")
		return
	}
	for _, provider := range providers {
		providerData, err := providerDatabase.ProviderQuery(provider, ".*")
		if err != nil {
			log.Printf("[dictionary] Could not get data for provider %s", provider)
			continue
		}
		for base, results := range providerData.Subdomains {
			for _, subdomain := range results {
				dictionary <- strings.TrimSuffix(subdomain, base)
			}
		}
	}
}

func addWordList(dictionary chan<- string, wordlistPath string) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		log.Printf("Error opening wordlist file %s", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		dictionary <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading wordlist file %s", err)
	}
}
