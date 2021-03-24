package tools

import (
	"fmt"
	"strings"
)

func ExtractHash(dnsEntry string, zone string) string {
	dnsEntry = strings.Split(dnsEntry, ".")[0]

	return strings.ToUpper(dnsEntry)
}

// NameToPath is a method which escapes a name, so we can use it as a filename
func NameToPath(filename string) string {
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, "/|\\| ", "_")

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
