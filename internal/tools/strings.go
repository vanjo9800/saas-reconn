package tools

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func CleanBase(base string) string {
	base = strings.ReplaceAll(base, "/", "_")
	return base
}

func ExtractHash(dnsEntry string, zone string) string {
	dnsEntry = strings.Split(dnsEntry, ".")[0]

	return strings.ToUpper(dnsEntry)
}

func LineCount(file string) (count int) {
	reader, err := os.Open(file)
	if err != nil {
		log.Printf("Could not open file %s", file)
		return count
	}

	buf := make([]byte, 32*1024)
	count = 0
	lineSep := []byte{'\n'}

	for {
		c, err := reader.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count

		case err != nil:
			return count
		}
	}
}

// NameToPath is a method which escapes a name, so we can use it as a filename
func NameToPath(filename string) string {
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, "/", "_")
	escapedName = strings.ReplaceAll(escapedName, "\\", "_")
	escapedName = strings.ReplaceAll(escapedName, " ", "_")

	return escapedName
}

func NotIncluded(data []string, includedPool []string) (notIncluded []string) {
	included := make(map[string]bool)

	for _, name := range includedPool {
		included[name] = true
	}

	for _, name := range data {
		if _, ok := included[name]; !ok {
			notIncluded = append(notIncluded, name)
		}
	}

	return notIncluded
}

func ToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func UniqueStrings(arr []string) []string {
	flags := make(map[string]bool)
	for _, element := range arr {
		flags[element] = true
	}

	var uniqueElements []string
	for element := range flags {
		uniqueElements = append(uniqueElements, element)
	}

	return uniqueElements
}

func URLFromSubdomainEntry(subdomain string) string {
	if strings.HasPrefix(subdomain, "http") {
		return subdomain
	}
	return fmt.Sprintf("http://%s/", subdomain)
}
