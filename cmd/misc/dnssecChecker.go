package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"saasreconn/pkg/zonewalk"
	"strings"
	"sync"
	"time"
)

const csvDomainPosition = 2

func updateRecord(record []string, newData string) (updatedRecord []string) {
	for i := 0; i <= csvDomainPosition; i++ {
		updatedRecord = append(updatedRecord, record[i])
	}
	updatedRecord = append(updatedRecord, newData)
	updatedRecord = append(updatedRecord, record[(csvDomainPosition+1):]...)

	return updatedRecord
}

func main() {

	// Read flags
	inputFile := flag.String("in", "", "path to CSV file to read domains from")
	output := flag.String("out", "", "path to where to write results")
	limit := flag.Int("limit", 10, "limit the number of domains to look at")
	flag.Parse()

	if *inputFile == "" {
		log.Fatal("Please select an input file!")
	}

	if *output == "" {
		*output = strings.TrimSuffix(*inputFile, ".csv") + "_dnssec.csv"
	}

	inFile, err := os.Open(*inputFile)
	if err != nil {
		log.Fatalf("Could not open file %s: %s", *inputFile, err)
	}
	outFile, err := os.Create(*output)
	if err != nil {
		log.Fatalf("Could not open file %s: %s", *output, err)
	}
	defer outFile.Close()

	inputReader := csv.NewReader(inFile)
	var writeLock sync.Mutex
	outputWriter := csv.NewWriter(outFile)
	defer outputWriter.Flush()
	// Read header
	header, err := inputReader.Read()
	if err != nil {
		log.Fatalf("Coult not read input file header %s", err)
	}
	updatedHeader := updateRecord(header, "dnssec")
	if err := outputWriter.Write(updatedHeader); err != nil {
		log.Fatalf("Error writing new header to file: %s", err)
	}
	start := time.Now()
	tick := time.Tick(time.Second)
	count := 0
	dnsResponses := make(chan []string, 5)
	dnsClients := make(chan bool, 10)
	var sentQueriesLock sync.Mutex
	sentDNSqueries := 0
	var dnsAnswersLock sync.Mutex
	dnsAnswers := 0
	finished := false
	var dnsWorkers sync.WaitGroup
	for !finished {

		select {
		case <-tick:
			fmt.Printf("Count %d, sent queries %d, collected answers %d, elapsed time %s\n", count, sentDNSqueries, dnsAnswers, time.Since(start))
		default:
			record, err := inputReader.Read()
			if err == io.EOF {
				finished = true
				break
			}
			domain := record[csvDomainPosition]
			if domain == "" {
				continue
			}

			dnsWorkers.Add(1)
			go func(record []string) {
				dnsClients <- true
				defer func() {
					<-dnsClients
				}()
				sentQueriesLock.Lock()
				sentDNSqueries++
				sentQueriesLock.Unlock()
				domain := record[csvDomainPosition]
				dnssecType, _, _ := zonewalk.DetectDNSSECType(zonewalk.Config{
					Nameserver: "1.1.1.1:53",
					Verbose:    4,
					Zone:       domain,
				})
				dnsAnswersLock.Lock()
				dnsAnswers++
				dnsAnswersLock.Unlock()
				updatedRecord := updateRecord(record, dnssecType)
				dnsResponses <- updatedRecord
			}(record)
			go func(dnsWorkers *sync.WaitGroup) {
				defer dnsWorkers.Done()
				updatedRecord := <-dnsResponses
				if updatedRecord[csvDomainPosition+1] != "" {
					writeLock.Lock()
					defer writeLock.Unlock()
					if err := outputWriter.Write(updatedRecord); err != nil {
						log.Fatalf("Error writing updated record to file: %s", err)
					}
				}

			}(&dnsWorkers)
			count++
			if *limit > 0 && count == *limit {
				finished = true
			}
		}
	}
	fmt.Println("Finished loop and now waiting...")
	dnsWorkers.Wait()
}
