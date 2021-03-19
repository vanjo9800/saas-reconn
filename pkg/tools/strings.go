package tools

import (
	"fmt"
	"strings"
)

func CleanDomainName(name string) string {
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")

	return name
}

func ExtractHash(dnsEntry string, zone string) string {
	dnsEntry = strings.TrimSuffix(dnsEntry, ".")
	dnsEntry = strings.TrimSuffix(dnsEntry, "."+zone)

	return strings.ToUpper(dnsEntry)
}

// NameToPath is a method which escapes a name, so we can use it as a filename
func NameToPath(filename string) string {
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, "/|\\| ", "_")

	return escapedName
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
