package provider

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
)

// SaaSProvider is a class instance for SaaS providers
type SaaSProvider struct {
	Subdomain []string
	Urls      []string
	Checks    []string
}

// ReadProviders reads a SaaS providers list from a YAML config file
func ReadProviders(endpointConfig string) (providers map[string]SaaSProvider, err error) {
    yamlFile, err := ioutil.ReadFile(endpointConfig)
    if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
		return nil, err
	}
	
	providers = make(map[string]SaaSProvider)
    err = yaml.Unmarshal(yamlFile, providers)
    if err != nil {
		log.Fatalf("Unmarshal: %v", err)
    }

    return providers, nil
}
