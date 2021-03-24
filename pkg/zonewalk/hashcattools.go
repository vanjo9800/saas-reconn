package zonewalk

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const hashcatLocation = "data/hashcat/"

// ExportToHashcat takes a collection of gathered hashes for a zone and creates a Hashcat-compatible input file for them
func ExportToHashcat(hashes []string, zone string, salt string, iterations int) string {
	err := os.MkdirAll(hashcatLocation, os.ModePerm)
	if err != nil {
		log.Printf("[%s:%s:%d] Could not create hashcat directory %s", zone, salt, iterations, err)
		return ""
	}

	// now := time.Now()
	filePath := fmt.Sprintf("%s%s_%s_%d_%d.hashcat", hashcatLocation, zone, salt, iterations, 0) // now.Unix())

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

func runShellCommand(command string, arguments []string) (string, string) {
	cmd := exec.Command(command, arguments...)
	fullCommand := cmd.String()
	stdoutReader, err := cmd.StdoutPipe()
	stderrReader, err := cmd.StderrPipe()

	if err != nil {
		log.Printf("Unexpected error initializing context `%s`: %s", fullCommand, err)
		return "", ""
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Unexpected error starting command `%s`: %s", fullCommand, err)
		return "", ""
	}

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	stdoutBuf.ReadFrom(stdoutReader)
	stderrBuf.ReadFrom(stderrReader)

	if err := cmd.Wait(); err != nil && stderrBuf.String() != "" {
		log.Printf("Unexpected error executing command `%s`: %s, Err: %s", fullCommand, err, stderrBuf.String())
		return "", ""
	}

	return stdoutBuf.String(), stderrBuf.String()
}

// RunHashcat runs hashcat with our internal dictionaries against an input file with NSEC3 hashes
func RunHashcat(config Config, inputFile string) map[string]string {
	// Check if hashcat is installed
	versionOut, versionErr := runShellCommand("hashcat_m1", []string{"--version"})
	if versionOut == "" {
		log.Printf("Hashcat check failed with status %s", versionErr)
		return nil
	}
	matchedVersionString, err := regexp.MatchString(`v[\d.]+`, versionOut)
	if err != nil || !matchedVersionString {
		log.Printf("Hashcat output `%s` does not match a version number", versionOut)
		return nil
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
		runShellCommand("hashcat_m1", []string{"-O", "-m8300", "-a0", fmt.Sprintf("--potfile-path=data/hashcat/%s.pot", strings.TrimPrefix(inputFile, hashcatLocation)), inputFile, wordlist})
	}
	if config.Verbose >= 3 {
		fmt.Println()
	}

	hashcatPot, _ := runShellCommand("hashcat_m1", []string{"-O", "-m8300", "-a0", fmt.Sprintf("--potfile-path=data/hashcat/%s.pot", strings.TrimPrefix(inputFile, hashcatLocation)), inputFile, "--show"})

	guessed := make(map[string]string)
	for _, guess := range strings.Split(hashcatPot, "\n") {
		if guess == "" {
			continue
		}
		guessParts := strings.Split(guess, ":")
		hash := strings.ToUpper(guessParts[0])
		plaintext := guessParts[4]
		guessed[hash] = plaintext
	}
	return guessed
}

func CleanHashcatDir() {
	os.RemoveAll(hashcatLocation)
}
