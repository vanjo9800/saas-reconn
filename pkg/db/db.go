package db

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Database is our data management class
type Database struct {
	initialised bool
	root        string
}

// nameToPath is a method which escapes a name, so we can use it as a filename
func nameToPath(filename string) string {
	// Escape symbols
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, " ", " ")
	escapedName = strings.ReplaceAll(escapedName, "\\", "_")
	escapedName = strings.ReplaceAll(escapedName, "/", " ")

	return escapedName
}

// NewDatabase constructs a new uninitialised database
func NewDatabase() *Database {
	return &Database{
		initialised: false,
		root:        "data/db/",
	}
}

// Initialise the database main folder
func (db *Database) Initialise() bool {

	if db.initialised {
		return true
	}

	if _, err := os.Stat(db.root); os.IsNotExist(err) {
		err := os.Mkdir(db.root, 0755)
		if err != nil {
			log.Fatal(err)
			return false
		}
	}
	db.initialised = true

	return db.initialised
}

// GetAll returns all providers in a database
func (db *Database) GetAll() (providers []string) {
	err := filepath.Walk(db.root, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			path = strings.TrimPrefix(path, db.root)
			path = strings.TrimSuffix(path, ".json")
			providers = append(providers, path)
		}
		return nil
	})

	if err == nil {
		return providers
	}

	log.Printf("There was an error getting all providers from database %s", err)
	return []string{}
}

func (db *Database) fetchDataForProvider(providerName string) (providerData *ProviderData, err error) {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return nil, errors.New("Could not initialise database")
	}

	data, err := ioutil.ReadFile(db.root + nameToPath(providerName) + ".json")
	if err != nil {
		log.Printf("[%s] Could not find existing provider data", providerName)
		return EmptyProviderData(providerName), nil
	}

	return ProviderDataFromJSON(data)
}

// ProviderQuery queries the stored data of a provider for matches given a regular expression from the user
func (db *Database) ProviderQuery(providerName string, domainPattern string) (providerData *ProviderData, err error) {
	providerSavedData, err := db.fetchDataForProvider(providerName)
	if err != nil {
		log.Fatal("There was an error fetching data for provider " + providerName)
		return nil, errors.New("There was an error fetching data for provider " + providerName)
	}

	return providerSavedData.query(domainPattern), nil
}

// SaveProviderData saves the current data to the data directory
func (db *Database) saveProviderData(data *ProviderData) error {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return errors.New("Could not initialise database")
	}

	dataJSON, err := data.ToJSON()
	if err != nil {
		log.Fatal("Could not convert provider data to JSON for provider " + data.ProviderName)
		return err
	}

	err = ioutil.WriteFile(db.root+nameToPath(data.ProviderName)+".json", dataJSON, 0755)
	if err != nil {
		log.Fatal("Failed to write provider data file for provider " + data.ProviderName)
		return err
	}

	return nil
}

// UpdateProvider updates the currently stored data for a provider and returns the difference between the new and old version
func (db *Database) UpdateProvider(providerName string, rootDomain string, names []Subdomain) (dataDiff *DataDiff, err error) {
	providerData, err := db.fetchDataForProvider(providerName)
	if err != nil {
		log.Fatal("There was an error fetching data for provider " + providerName)
		return nil, err
	}

	dataDiff = providerData.updateDomainEntries(rootDomain, names)

	err = db.saveProviderData(providerData)
	if err != nil {
		log.Fatal("Could not update provider data for provider " + providerName)
		return nil, err
	}

	return dataDiff, nil
}

// DeleteProvider deletes provider data
func (db *Database) DeleteProvider(providerName string) bool {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return false
	}

	// Check if provider data exists and delete only if there
	if _, err := os.Stat(db.root); os.IsExist(err) {
		err := os.Remove(db.root + nameToPath(providerName) + ".json")
		if err != nil {
			log.Fatal("Could not detele data file")
			return false
		}
		return true
	}

	return true
}
