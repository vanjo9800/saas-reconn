package zonewalk

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"saasreconn/pkg/tools"
	"strings"
	"time"
)

const hashcatLocation = "data/hashcat/"

// ExportToHashcat takes a collection of gathered hashes for a zone and creates a Hashcat-compatible input file for them
func ExportToHashcat(hashes []string, zone string, salt string, iterations int) string {
	err := os.MkdirAll(hashcatLocation, os.ModePerm)
	if err != nil {
		log.Printf("[%s:%s:%d] Could not create hashcat directory %s", zone, salt, iterations, err)
		return ""
	}

	now := time.Now()
	filePath := fmt.Sprintf("%s%s_%s_%d_%d.hashcat", hashcatLocation, zone, salt, iterations, now.Unix())

	hashcatFile, err := os.Create(filePath)
	if err != nil {
		log.Printf("[%s:%s:%d] Could not create hashcat file %s", zone, salt, iterations, err)
		return ""
	}
	defer hashcatFile.Close()

	for _, hash := range hashes {
		_, err = hashcatFile.WriteString(fmt.Sprintf("%s:.%s:%s:%d\n", strings.ToLower(hash), zone, salt, iterations))
		if err != nil {
			log.Printf("[%s:%s:%d] Error writing to hashcat file %s", zone, salt, iterations, err)
			return ""
		}
	}

	return filePath
}

// RunHashcat runs hashcat with our internal dictionaries against an input file with NSEC3 hashes
func RunHashcat(config Config, inputFile string) (guessed map[string]string, dictionarySize int) {
	// Check if hashcat is installed
	versionOut, versionErr := tools.RunShellCommand("hashcat_m1", []string{"--version"})
	if versionOut == "" {
		log.Printf("Hashcat check failed with status %s", versionErr)
		return nil, 0
	}
	matchedVersionString, err := regexp.MatchString(`v[\d.]+`, versionOut)
	if err != nil || !matchedVersionString {
		log.Printf("Hashcat output `%s` does not match a version number", versionOut)
		return nil, 0
	}

	// Build dictionary lists
	var wordlists []string
	if config.Wordlist != "" && config.Wordlist != "provider-database" {
		wordlists = append(wordlists, config.Wordlist)
	} else {
		wordlists = WordlistBank()
	}
	if config.Wordlist == "provider-database" || config.Wordlist == "" {
		providersWordlist := "provider_dictionary.txt"
		wordlists = append(wordlists, hashcatLocation+providersWordlist)
		exportProviderData(hashcatLocation, providersWordlist)
	}

	for _, wordlist := range wordlists {
		if config.Verbose >= 3 {
			fmt.Printf("\rPassing wordlist %s...\r", wordlist)
		}
		tools.RunShellCommand("hashcat_m1", []string{"-O", "-m8300", "-a0", fmt.Sprintf("--potfile-path=data/hashcat/%s.pot", strings.TrimPrefix(inputFile, hashcatLocation)), inputFile, wordlist})
		dictionarySize += tools.LineCount(wordlist)
	}
	if config.Verbose >= 3 {
		fmt.Println()
	}

	hashcatPot, _ := tools.RunShellCommand("hashcat_m1", []string{"-O", "-m8300", "-a0", fmt.Sprintf("--potfile-path=data/hashcat/%s.pot", strings.TrimPrefix(inputFile, hashcatLocation)), inputFile, "--show"})

	guessed = make(map[string]string)
	for _, guess := range strings.Split(hashcatPot, "\n") {
		if guess == "" {
			continue
		}
		guessParts := strings.Split(guess, ":")
		hash := strings.ToUpper(guessParts[0])
		plaintext := guessParts[4]
		guessed[hash] = plaintext
	}
	return guessed, dictionarySize
}

func CleanHashcatDir() {
	os.RemoveAll(hashcatLocation)
}
