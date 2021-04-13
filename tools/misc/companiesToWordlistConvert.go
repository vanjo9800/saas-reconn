package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func main() {

	// Read flags
	inputFile := flag.String("in", "", "path to CSV file to read domains from")
	output := flag.String("out", "", "path to where to write results")
	csvPosition := flag.Int("pos", 2, "position of the domain in the csv")
	flag.Parse()

	if *inputFile == "" {
		log.Fatal("Please select an input file!")
	}

	if *output == "" {
		*output = strings.TrimSuffix(*inputFile, ".csv") + "_wordlist.txt"
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

	// Read header
	_, err = inputReader.Read()
	if err != nil {
		log.Fatalf("Coult not read input file header %s", err)
	}
	writer := bufio.NewWriter(outFile)

	for {
		record, err := inputReader.Read()
		if err == io.EOF {
			break
		}
		domain := record[*csvPosition]
		if domain == "" {
			continue
		}
		index := len(domain) - 1
		for domain[index] != '.' {
			index--
		}
		domain = domain[:index]
		_, err = writer.WriteString(domain + "\n")
		if err != nil {
			log.Fatalf("Got error while writing to a file. Err: %s", err.Error())
		}
	}
	writer.Flush()
	fmt.Println("Finished loop and now waiting...")
}
