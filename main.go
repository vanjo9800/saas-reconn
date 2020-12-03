package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/systems"
)

func nameToHosts() {

}

func hostsEnumeration(cfg *config.Config) []string {
	// Setup enumeration (from different lists)
	results := []string{}

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return results
	}
	sys.SetDataSources(datasrcs.GetAllSources(sys, true))

	e := enum.NewEnumeration(cfg, sys)
	if e == nil {
		return results
	}
	defer e.Close()

	e.Start()
	for _, o := range e.ExtractOutput(nil, false) {
		fmt.Println(o.Name)
		results = append(results, o.Name)
	}

	sort.Strings(results)
	return results
}

func hostsDNS() {

}

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// Setup the most basic amass configuration
	cfg := config.NewConfig()
	cfg.AddDomain("zoom.us")
	cfg.Verbose = true
	cfg.Log = log.New(os.Stderr, "Enumeration info: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg.Timeout = 1

	found := []string{}
	found = append(found, hostsEnumeration(cfg)...)

	for _, name := range found {
		fmt.Println(name)
	}

}
