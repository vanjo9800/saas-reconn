package db

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

func (db *Database) ProviderQuery(providerName string, domainName string) *ProviderData {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return nil
	}

	// Check provider data exists
	if _, err := os.Stat("db/"); os.IsNotExist(err) {
		return EmptyProviderData()
	}

	data, err := ioutil.ReadFile("db/" + NameToPath(providerName) + ".data")
	if err != nil {
		log.Fatal("Could not read provider data")
		return EmptyProviderData()
	}

	return BuildProviderDataResult(data, domainName)
}

func (db *Database) UpdateProvider(providerName string, names []string) []string {
	success := db.Initialise()
	if !success {
		log.Fatal("Could not initialise database")
		return false
	}

	// Read all current data
	currentState := db.ProviderQuery(providerName, "")
	currentNames = currentState.getNames()
	currentState.updateNames(names)

	return DomainNamesDiff(currentNames, names)

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
