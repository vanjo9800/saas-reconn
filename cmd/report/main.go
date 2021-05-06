package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"time"

	"saasreconn/internal/api"
	"saasreconn/internal/db"
	"saasreconn/internal/provider"
	"saasreconn/internal/report"
	"saasreconn/internal/tools"
)

const searchDNSCorporateConfidence = 2

func filterConfidence(foundSubdomains map[string][]db.Subdomain, confidenceThreshold int) map[string][]db.Subdomain {
	domainsReport := make(map[string][]db.Subdomain)
	for record, subdomains := range foundSubdomains {
		filteredSubdomainsForRecord := []db.Subdomain{}
		for _, subdomain := range subdomains {
			if subdomain.Confidence >= confidenceThreshold {
				filteredSubdomainsForRecord = append(filteredSubdomainsForRecord, subdomain)
			}
		}
		domainsReport[record] = filteredSubdomainsForRecord
	}
	return domainsReport
}

func filterEmptyKeys(foundSubdomains map[string][]db.Subdomain) map[string][]db.Subdomain {
	domainsReport := make(map[string][]db.Subdomain)
	for record, subdomains := range foundSubdomains {
		if len(subdomains) > 0 {
			domainsReport[record] = subdomains
		}
	}
	return domainsReport
}

func takeScreenshots(foundSubdomains map[string][]db.Subdomain) (domainsReport map[string][]db.Subdomain, count int) {
	count = 0
	domainsReport = make(map[string][]db.Subdomain)
	for record, subdomains := range foundSubdomains {
		filteredSubdomainsForRecord := []db.Subdomain{}
		for _, subdomain := range subdomains {
			var err error
			subdomain.Screenshot, err = tools.Base64ImageFromURL(tools.URLFromSubdomainEntry(subdomain.Name))
			if err != nil {
				subdomain.Screenshot = "N/A"
			}
			count++
			filteredSubdomainsForRecord = append(filteredSubdomainsForRecord, subdomain)
		}
		domainsReport[record] = filteredSubdomainsForRecord
	}

	return domainsReport, count
}

func exportProviderData(corporateName string, confidenceThreshold int, extended bool, resultsDatabase *db.Database, providers map[string]provider.SaaSProvider) (subdomainsReport []db.ProviderData) {
	for providerName := range providers {
		providerData, _ := resultsDatabase.ProviderQuery(providerName, tools.ProviderDomainRegex(corporateName, extended))
		subdomainsReport = append(subdomainsReport, *providerData)
	}
	return subdomainsReport
}

func searchDNSOtherSubdomains(corporateName string, verbosity int) []string {
	return api.SearchDNSQuery(tools.ProviderDomainText(corporateName), "starts", verbosity)
}

func main() {

	// Read flags
	confidenceThreshold := flag.Int("confidence-threshold", searchDNSCorporateConfidence, "confidence treshold")
	endpointsConfig := flag.String("endpoints-config", "configs/saas-endpoints.yaml", "a SaaS providers endpoints file")
	extended := flag.Bool("extended", false, "search for any subdomains matching corporate name")
	screenshot := flag.Bool("screenshot", true, "take page screenshots")
	noSearchDNS := flag.Bool("no-searchdns", false, "do not suggest other potential subdomains from SearchDNS")
	out := flag.String("outfile", "", "set a custom name for the report file")
	logfile := flag.String("logfile", "", "log just endpoint names")
	verbose := flag.Int("verbose", 2, "verbosity factor")
	flag.Parse()

	// Database setup
	resultsDatabase := db.NewDatabase()
	saasProviders, err := provider.ReadProviders(*endpointsConfig)
	if err != nil {
		log.Fatal("Could not fetch SaaS providers")
	}

	argsWithoutProg := flag.Args()
	if len(argsWithoutProg) == 0 {
		log.Fatalln("Please enter at least one corporate name to scan for.")
	}
	var writer *bufio.Writer
	if *logfile != "" {
		file, err := os.Create(fmt.Sprintf("reports/logs/%s", *logfile))
		if err != nil {
			log.Fatal(err)
		}
		writer = bufio.NewWriter(file)
	}
	for _, corporateName := range argsWithoutProg {

		fmt.Printf("Read \"%s\"\n", corporateName)
		fmt.Printf("Generating HTML report for \"%s\"\n", corporateName)
		start := time.Now()
		exportedSubdomains := exportProviderData(corporateName, *confidenceThreshold, *extended, resultsDatabase, saasProviders)
		if !*noSearchDNS {
			otherPotentialSubdomains := searchDNSOtherSubdomains(corporateName, *verbose)
			otherPotentialSubdomains = tools.NotIncluded(otherPotentialSubdomains, db.NamesFromProviderData(exportedSubdomains))
			otherPotentialSubdomains = tools.FilterTLDs(otherPotentialSubdomains, corporateName)
			otherPotentialSubdomains = tools.FilterNonAccessibleNames(otherPotentialSubdomains)
			otherPotentialSubdomains = tools.FilterCommonFPs(otherPotentialSubdomains, corporateName)
			exportedSubdomains = append(exportedSubdomains, db.ProviderData{
				Provider: "SearchDNS (search by corporate name)",
				Subdomains: map[string][]db.Subdomain{
					"searchdns": db.MapStringNamesToSubdomain(otherPotentialSubdomains, searchDNSCorporateConfidence, "SearchDNS (search by corporate name)"),
				},
			})
		}
		if *verbose >= 2 {
			fmt.Printf("Found %d potential names from search by corporate name in SearchDNS\n", len(db.NamesFromProviderData(exportedSubdomains)))
		}
		for index, providerSubdomain := range exportedSubdomains {
			exportedSubdomains[index].Subdomains = filterEmptyKeys(filterConfidence(providerSubdomain.Subdomains, *confidenceThreshold))
		}
		reportingNamesCount := len(db.NamesFromProviderData(exportedSubdomains))
		if *verbose >= 2 {
			fmt.Printf("%d names left after confidence filtering\n", reportingNamesCount)
			fmt.Printf("About to take %d screenshots...\n", reportingNamesCount)
		}
		takenScreenshots := 0
		providerNames := []string{}
		for index, providerSubdomain := range exportedSubdomains {
			if !*screenshot {
				break
			}
			if len(providerSubdomain.Subdomains) == 0 {
				continue
			}
			if *verbose >= 2 {
				fmt.Printf("\rFinished %d/%d", takenScreenshots, reportingNamesCount)
			}
			providerNames = append(providerNames, providerSubdomain.Provider)
			var count int
			exportedSubdomains[index].Subdomains, count = takeScreenshots(providerSubdomain.Subdomains)
			takenScreenshots += count
		}
		if *logfile != "" {
			sort.Strings(providerNames)
			for _, name := range providerNames {
				_, err := writer.WriteString(name + "\n")
				if err != nil {
					log.Printf("Got error while writing to a log. Err: %s", err.Error())
				}
			}
		}
		if *verbose >= 2 {
			fmt.Println("\nDone!")
		}

		outputFile := *out
		if outputFile == "" {
			timestamp := time.Now().Format(time.RFC3339)
			re := regexp.MustCompile(`-|:|`)
			timestamp = re.ReplaceAllString(timestamp, "")
			outputFile = fmt.Sprintf("%s-%s", corporateName, timestamp)
		}
		report.ExportToHTML(exportedSubdomains, corporateName, outputFile)
		fmt.Printf("HTML generation took %s\n", time.Since(start))
		fmt.Printf("Results file located under reports/%s\n", outputFile)
	}
	if *logfile != "" {
		writer.Flush()
	}

}
