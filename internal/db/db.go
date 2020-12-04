package saasreconn

import (
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

func (db *Database) FetchDataForProvider(providerName string) *ProviderData {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return nil, 1
	}

	data, err := ioutil.ReadFile("db/" + NameToPath(providerName) + ".data")
	if err != nil {
		log.Fatal("Could not read provider data")
		return EmptyProviderData(providerName)
	}

	return ProvideDataFromJSON(data)
}

func (db *Database) ProviderQuery(providerName string, domainPattern string) *ProviderData {
	providerData, err := db.FetchDataForProvider(providerName)
	if err != nil {
		log.Fatal("There was an error fetching data for provider " + providerName)
		return nil, 1
	}

	return providerSavedData.query(domainPattern)
}

func (db *Database) SaveProviderData(data ProviderData) {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return 1
	}

	dataJson, err = data.ToJSON()
	if err != nil {
		log.Fatal("Could not convert provider data to JSON for provider " + data.providerName)
		return 1
	}

	err := ioutil.WriteFile("db/"+NameToPath(data.providerName)+".data", dataJson, 0755)
	if err != nil {
		log.Fatal("Failed to write provider data file for provider " + data.providerName)
		return 1
	}
}

func (db *Database) UpdateProvider(providerName string, rootDomain string, names []string) *DataDiff {
	providerData, err = db.FetchDataForProvider(providerName)
	if err != nil {
		log.Fatal("There was an error fetching data for provider " + providerName)
		return nil, 1
	}

	dataDiff := providerData.updateDomainEntries(names)

	err := SaveProviderData(providerData)
	if err != nil {
		log.Fatal("Could not update provider data for provider " + providerName)
		return nil, 1
	}

	return dataDiff
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
