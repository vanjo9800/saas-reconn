package tools

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

// See RFC1035 (https://tools.ietf.org/html/rfc1035)
// 52 letters (a-zA-Z), 10 digits (0-9), hyphen (-), underscore (_)
const DomainNameCharset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

var TLDExtensions []string = []string{
	".bg",
	".com",
	".co",
	".co.uk",
	".de",
	".es",
	".fr",
	".it",
	".jp",
	".om",
}

var commonFPExtensions []string = []string{}

func CleanDomainName(name string) string {
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	return name
}

func FilterKnownFPs(names []string, corporateName string) (filteredNames []string) {
	knownFPExtensions := make(map[string]bool)
	for _, FPExtension := range commonFPExtensions {
		knownFPExtensions[fmt.Sprintf("%s%s", corporateName, FPExtension)] = true
	}
	for _, name := range names {
		if _, ok := knownFPExtensions[name]; !ok {
			filteredNames = append(filteredNames, name)
		}
	}

	return filteredNames
}

func FilterNonResolvingNames(names []string) (filteredNames []string) {
	for _, name := range names {
		url, err := url.Parse(fmt.Sprintf("http://%s/", name))
		if err != nil {
			log.Printf("Failed parsing URL `%s` when filtering: %s", url, err)
			continue
		}
		address, err := net.LookupHost(url.Hostname())
		if err != nil || len(address) == 0 {
			continue
		}
		filteredNames = append(filteredNames, name)
	}
	return filteredNames
}

func FilterTLDs(names []string, corporateName string) (filteredNames []string) {
	tldNames := make(map[string]bool)
	for _, tld := range TLDExtensions {
		tldNames[fmt.Sprintf("%s%s", corporateName, tld)] = true
	}
	for _, name := range names {
		if _, ok := tldNames[name]; !ok {
			filteredNames = append(filteredNames, name)
		}
	}

	return filteredNames
}

func ProviderDomainRegex(name string, extended bool) string {
	if extended {
		return fmt.Sprintf("%s[0-9._-]", name)
	}
	return fmt.Sprintf("%s[._-]", name)
}

func ProviderDomainText(name string) string {
	return fmt.Sprintf("%s.", name)
}
