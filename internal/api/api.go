package api

import (
	"io/ioutil"
	"log"

	"github.com/OWASP/Amass/v3/config"
	"gopkg.in/yaml.v2"
)

type apiCredentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Key      string `yaml:"apikey"`
	Secret   string `yaml:"secret"`
}

func SetupAPICredentials(cfg *config.Config, credentialsFile string) error {

	// Read YAML configuration
	yamlFile, err := ioutil.ReadFile(credentialsFile)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
		return err
	}

	credentials := make(map[string]apiCredentials)
	err = yaml.Unmarshal(yamlFile, credentials)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	for provider, details := range credentials {
		providerConfig := cfg.GetDataSourceConfig(provider)
		if details.Username != "" {
			providerConfig.AddCredentials(&config.Credentials{
				Name: "username",
				Key:  details.Username,
			})
		}
		if details.Password != "" {
			providerConfig.AddCredentials(&config.Credentials{
				Name: "password",
				Key:  details.Password,
			})
		}
		if details.Key != "" {
			providerConfig.AddCredentials(&config.Credentials{
				Name: "apikey",
				Key:  details.Key,
			})
		}
		if details.Secret != "" {
			providerConfig.AddCredentials(&config.Credentials{
				Name: "secret",
				Key:  details.Secret,
			})
		}
	}

	return nil
}
