package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"saasreconn/pkg/cache"
	"saasreconn/pkg/zonewalk"
)

const zonewalkCacheDirectory = "data/cache/zonewalk/"

func getCachedZones() (list []string) {
	err := filepath.Walk(zonewalkCacheDirectory, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".json") {
			cleanPath := strings.TrimSuffix(filepath.Base(path), ".json")
			list = append(list, cleanPath)
		}
		return nil
	})
	if err != nil {
		log.Printf("Could not read zonewalk caches from directory %s", err)
	}
	return list
}

func lineCount(file string) (count int) {
	reader, err := os.Open(file)
	if err != nil {
		log.Printf("Could not open file %s", file)
		return count
	}

	buf := make([]byte, 32*1024)
	count = 0
	lineSep := []byte{'\n'}

	for {
		c, err := reader.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count

		case err != nil:
			return count
		}
	}
}

func main() {

	// Read flags
	wordlist := flag.String("wordlist", "", "path to wordlist to evaluate")
	output := flag.String("out", "wordlist-evaluation.csv", "path to CSV output")
	verbose := flag.Int("verbose", 1, "verbosity factor")
	flag.Parse()

	var wordlists []string
	if *wordlist == "" {
		wordlists = zonewalk.WordlistBank()
	} else {
		wordlists = append(wordlists, *wordlist)
	}

	stats := [][]string{}
	cachedZones := getCachedZones()
	zonesTitle := []string{"Wordlist", "Size"}
	for _, zone := range cachedZones {
		zonesTitle = append(zonesTitle, zone)
	}
	stats = append(stats, zonesTitle)

	cachedResults := cache.NewCache()
	for _, wordlist := range wordlists {
		fmt.Printf("Examining wordlist %s\n", wordlist)
		wordlistData := []string{filepath.Base(wordlist), fmt.Sprintf("%d", lineCount(wordlist))}
		for _, zone := range cachedZones {
			zoneData, err := cachedResults.FetchZoneWalkForZone(zone)
			if err != nil {
				log.Printf("[%s] Could not get cached data for zone", zone)
				continue
			}
			config := zonewalk.Config{
				Cache:    true,
				Hashcat:  false, //*hashcat,
				Mode:     3,
				Verbose:  *verbose,
				Wordlist: wordlist,
				Zone:     zone,
			}
			for params := range zoneData {
				salt := strings.Split(params, ":")[0]
				iterations, _ := strconv.Atoi(strings.Split(params, ":")[1])
				guessed := zonewalk.Nsec3ZoneWalking(config, salt, iterations)
				wordlistData = append(wordlistData, fmt.Sprintf("%d", len(guessed)))
				fmt.Printf("%d names guessed for zone %s\n", len(guessed), zone)
			}

		}
		stats = append(stats, wordlistData)
	}

	file, err := os.Create(*output)
	if err != nil {
		log.Fatal(err)
	}
	writer := bufio.NewWriter(file)
	w := csv.NewWriter(writer)

	for _, record := range stats {
		if err := w.Write(record); err != nil {
			log.Fatalln("error writing record to csv:", err)
		}
	}

	// Write any buffered data to the underlying writer (standard output).
	w.Flush()

	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
}
