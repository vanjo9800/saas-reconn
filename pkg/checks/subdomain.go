package checks

import (
	"fmt"
	"log"
)

type AddressBase interface {
	GetBase() string
	GetUrl(name string) string
}

type SubdomainBase string

func (s SubdomainBase) GetBase() string {
	return string(s)
}

func (s SubdomainBase) GetUrl(name string) string {
	return fmt.Sprintf("http://%s.%s", name, string(s))
}

type UrlBase string

func (s UrlBase) GetBase() string {
	return string(s)
}

func (s UrlBase) GetUrl(name string) string {
	return fmt.Sprintf("http://%s%s", string(s), name)
}

type SubdomainRange struct {
	Base     AddressBase
	Prefixes []string
}

func (data SubdomainRange) Dump() {
	if len(data.Prefixes) == 0 {
		return
	}

	log.Printf("Subdomains of %s", data.Base)
	for _, prefix := range data.Prefixes {
		log.Printf("  - %s", data.Base.GetUrl(prefix))
	}
}
