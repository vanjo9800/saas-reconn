package zonewalk

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
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
		_, err = hashcatFile.WriteString(fmt.Sprintf("%s:.%s:%s:%d\n", hash, zone, salt, iterations))
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
	log.Printf("Running command `%s`", command)
	if err := cmd.Start(); err != nil {
		log.Printf("Unexpected error starting command `%s`: %s", fullCommand, err)
		return "", ""
	}

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	stdoutBuf.ReadFrom(stdoutReader)
	stderrBuf.ReadFrom(stderrReader)

	log.Printf("Out: %s, Err: %s", stdoutBuf.String(), stderrBuf.String())

	if err := cmd.Wait(); err != nil {
		log.Printf("Unexpected error executing command `%s`: %s", fullCommand, err)
		return "", ""
	}

	return stdoutBuf.String(), stderrBuf.String()
}

// RunHashcat runs hashcat with our internal dictionaries against an input file with NSEC3 hashes
func RunHashcat(inputFile string) map[string]string {
	// Check if hashcat is installed
	versionOut, versionErr := runShellCommand("hashcat", []string{"--version"})
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
	wordlists := WordlistBank()
	providersWordlist := "provider_dictionary.txt"
	wordlists = append(wordlists, hashcatLocation+providersWordlist)
	exportProviderData(hashcatLocation, providersWordlist)

	for _, wordlist := range wordlists {
		crackingOut, crackingErr := runShellCommand("hashcat", []string{"-m 8300", "-a 0", inputFile, wordlist})
		log.Printf("Stdout: %s", crackingOut)
		log.Printf("Stderr: %s", crackingErr)
	}

	return nil
}

func CleanHashcatDir() {
	os.RemoveAll(hashcatLocation)
}
