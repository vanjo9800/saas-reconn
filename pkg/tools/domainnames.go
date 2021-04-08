package tools

import (
	"fmt"
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

var FPExtensions []string = []string{
	".meb.gov.tr",                 // in http://aol.meb.gov.tr
	".hkelectric.com",             // in http://aol.hkelectric.com
	".cellmaps.com",               // in http://verizon.cellmaps.com
	".aleado.com",                 // in http://yahoo.aleado.com
	".aleado.ru",                  // in http://yahoo.aleado.ru
	".digitalmktg.com.hk",         // in http://yahoo.digitalmktg.com.hk
	".yellowpages.ca",             // in http://yahoo.yellowpages.ca
	".brand.edgar-online.com",     // in http://yahoo.brand.edgar-online.com
	".tu-sofia.bg",                // in http://cisco.tu-sofia.bg
	".num.edu.mn",                 // in http://cisco..num.edu.mn
	".hackfest.nttltd.global.ntt", // in http://cisco.hackfest.nttltd.global.ntt
	".dowlis.punchouthub.co.uk",   // in http://cisco.dowlis.punchouthub.co.uk
	".tosinso.com",                // in http://cisco.tosinso.com
	".ofppt.info",                 // in http://cisco.ofppt.info
	".ctcnvk.ro",                  // in http://cisco.ctcnvk.ro
}

func CleanDomainName(name string) string {
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	return name
}

func FilterCommonFPs(names []string, corporateName string) (filteredNames []string) {
	foundFPExtensions := make(map[string]bool)
	for _, FPExtension := range FPExtensions {
		foundFPExtensions[fmt.Sprintf("%s%s", corporateName, FPExtension)] = true
	}
	for _, name := range names {
		if _, ok := foundFPExtensions[name]; !ok {
			filteredNames = append(filteredNames, name)
		}
	}

	return filteredNames
}

func FilterNonAccessibleNames(names []string) (filteredNames []string) {
	for _, name := range names {
		url := fmt.Sprintf("http://%s/", name)
		cleanBody := HttpSyncRequest(url, 1)
		if len(cleanBody) == 0 {
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
		return fmt.Sprintf("^%s[0-9._-]", name)
	}
	return fmt.Sprintf("^%s[._-]", name)
}

func ProviderDomainText(name string) string {
	return fmt.Sprintf("%s.", name)
}
