package zonewalk

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"saasreconn/pkg/db"
	"strings"
)

const wordlistDirectory string = "resources/wordlists/"

// BuildLocalDictionary builds a dictionary channel for a local NSEC3 hash dictionary attack
func BuildLocalDictionary(wordlist string, dictionary chan<- string) {
	var wordlists []string
	if wordlist == "" {
		wordlists = WordlistBank()
	} else {
		wordlists = append(wordlists, wordlist)
	}
	for _, list := range wordlists {
		addWordList(list, dictionary)
	}
	addProviderData(dictionary)
	close(dictionary)
}

func cleanProviderName(name string, base string) string {
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimSuffix(name, base)
	name = strings.TrimSuffix(name, ".")

	return name
}

func addProviderData(dictionary chan<- string) {
	providerDatabase := db.NewDatabase()
	providerDatabase.Initialise()

	providers := providerDatabase.GetAll()
	for _, provider := range providers {
		providerData, err := providerDatabase.ProviderQuery(provider, ".*")
		if err != nil {
			log.Printf("[dictionary] Could not get data for provider %s", provider)
			continue
		}
		for base, results := range providerData.Subdomains {
			for _, subdomain := range results {
				dictionary <- cleanProviderName(subdomain.Name, base)
			}
		}
	}
}

func exportProviderData(path string, filename string) {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		log.Printf("ExportProviderData: Could not create provider dictionary data directory %s: %s", filename, err)
		return
	}

	providerDictionary, err := os.Create(path + filename)
	if err != nil {
		log.Printf("ExportProviderData: Could not create provider dictionary file %s: %s", filename, err)
		return
	}
	defer providerDictionary.Close()

	providerDatabase := db.NewDatabase()
	providerDatabase.Initialise()

	providers := providerDatabase.GetAll()
	for _, provider := range providers {
		providerData, err := providerDatabase.ProviderQuery(provider, ".*")
		if err != nil {
			log.Printf("[dictionary] Could not get data for provider %s", provider)
			continue
		}
		for base, results := range providerData.Subdomains {
			for _, subdomain := range results {
				_, err := providerDictionary.WriteString(cleanProviderName(subdomain.Name, base) + "\n")
				if err != nil {
					log.Printf("ExportProviderData: Error writing to provider dictionary file %s: %s", filename, err)
					return
				}
			}
		}
	}
}

func WordlistBank() (list []string) {
	err := filepath.Walk(wordlistDirectory, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".txt") {
			list = append(list, path)
		}
		return nil
	})
	if err != nil {
		log.Printf("Could not read wordlists from directory %s", err)
	}
	return list
}

func addWordList(filepath string, dictionary chan<- string) {
	file, err := os.Open(filepath)
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
