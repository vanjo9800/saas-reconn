package db

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type Database struct {
	initialised bool
}

// Constructor
func NewDatabase() *Database {
	return &Database{
		initialised: false,
	}
}

func NameToPath(filename string) string {
	// Escape symbols
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, " ", " ")
	escapedName = strings.ReplaceAll(escapedName, "\\", "_")
	escapedName = strings.ReplaceAll(escapedName, "/", " ")

	return escapedName
}

// Create the database directory structure
func (db *Database) Initialise() bool {

	if db.initialised {
		return true
	}

	if _, err := os.Stat("db/"); os.IsNotExist(err) {
		err := os.Mkdir("db/", 0755)
		if err != nil {
			log.Fatal(err)
			return false
		}
		db.initialised = true
	}

	return db.initialised
}

func (db *Database) FetchDataForProvider(providerName string) (providerData *ProviderData, err error) {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return nil, errors.New("Could not initialise database")
	}

	data, err := ioutil.ReadFile("db/" + NameToPath(providerName) + ".data")
	if err != nil {
		log.Fatal("Could not read provider data")
		return EmptyProviderData(providerName), nil
	}

	return ProvideDataFromJSON(data)
}

func (db *Database) ProviderQuery(providerName string, domainPattern string) (providerData *ProviderData, err error) {
	providerSavedData, err := db.FetchDataForProvider(providerName)
	if err != nil {
		log.Fatal("There was an error fetching data for provider " + providerName)
		return nil, errors.New("There was an error fetching data for provider " + providerName)
	}

	return providerSavedData.query(domainPattern), nil
}

func (db *Database) SaveProviderData(data *ProviderData) error {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return errors.New("Could not initialise database")
	}

	dataJson, err := data.ToJSON()
	if err != nil {
		log.Fatal("Could not convert provider data to JSON for provider " + data.providerName)
		return err
	}

	err = ioutil.WriteFile("db/"+NameToPath(data.providerName)+".data", dataJson, 0755)
	if err != nil {
		log.Fatal("Failed to write provider data file for provider " + data.providerName)
		return err
	}

	return nil
}

func (db *Database) UpdateProvider(providerName string, rootDomain string, names []string) (dataDiff *DataDiff, err error) {
	providerData, err := db.FetchDataForProvider(providerName)
	if err != nil {
		log.Fatal("There was an error fetching data for provider " + providerName)
		return nil, err
	}

	dataDiff = providerData.updateDomainEntries(rootDomain, names)

	err = db.SaveProviderData(providerData)
	if err != nil {
		log.Fatal("Could not update provider data for provider " + providerName)
		return nil, err
	}

	return dataDiff, nil
}

func (db *Database) DeleteProvider(providerName string) bool {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return false
	}

	// Check if provider data exists and delete only if there
	if _, err := os.Stat("db/"); os.IsExist(err) {
		err := os.Remove("db/" + NameToPath(providerName) + ".data")
		if err != nil {
			log.Fatal("Could not detele data file")
			return false
		}
		return true
	}

	return true
}
