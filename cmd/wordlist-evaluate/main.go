package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
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

func main() {

	// Read flags
	wordlist := flag.String("wordlist", "", "path to wordlist to evaluate")
	hashcat := flag.Bool("hashcat", true, "use hashcat for hash reversing")
	output := flag.String("out", "wordlist-evaluation.csv", "path to CSV output")
	verbose := flag.Int("verbose", 1, "verbosity factor")
	flag.Parse()

	var wordlists []string
	if *wordlist == "" {
		wordlists = zonewalk.WordlistBank()
		wordlists = append(wordlists, "provider-database")
	} else {
		wordlists = append(wordlists, *wordlist)
	}

	stats := [][]string{}
	cachedZones := getCachedZones()
	cachedResults := cache.NewCache()
	zonesTitle := []string{"Wordlist", "Size"}
	zonesSizes := []string{"Zone parameters and size", ""}
	for _, zone := range cachedZones {
		zoneData, err := cachedResults.FetchZoneWalkForZone(zone)
		if err != nil {
			log.Printf("[%s] Could not get cached data for zone", zone)
			continue
		}
		for params, data := range zoneData {
			salt := strings.Split(params, ":")[0]
			iterations, _ := strconv.Atoi(strings.Split(params, ":")[1])
			zoneName := zone
			if iterations == -1 {
				zoneName = fmt.Sprintf("%s (NSEC)", zone)
				zonesSizes = append(zonesSizes, fmt.Sprintf("Size %d", len(data.Guessed)))
			} else {
				zoneName = fmt.Sprintf("%s (NSEC3)", zone)
				zonesSizes = append(zonesSizes, fmt.Sprintf("Salt size %d\nIterations %d\nHashes %d", len(salt), iterations, len(data.Hashes)))
			}
			zonesTitle = append(zonesTitle, zoneName)
		}
	}
	stats = append(stats, zonesTitle)
	stats = append(stats, zonesSizes)

	for _, wordlist := range wordlists {
		fmt.Printf("\nExamining wordlist %s\n", wordlist)
		wordlistData := []string{filepath.Base(wordlist), "0"}
		wordlistSize := 0
		for _, zone := range cachedZones {
			zoneData, err := cachedResults.FetchZoneWalkForZone(zone)
			if err != nil {
				log.Printf("[%s] Could not get cached data for zone", zone)
				continue
			}
			config := zonewalk.Config{
				MappingCache: true,
				GuessesCache: false,
				UpdateCache:  false,
				Hashcat:      *hashcat,
				Mode:         3,
				Verbose:      *verbose,
				Wordlist:     wordlist,
				Zone:         zone,
			}
			for params := range zoneData {
				salt := strings.Split(params, ":")[0]
				iterations, _ := strconv.Atoi(strings.Split(params, ":")[1])
				var guessed []string
				if iterations == -1 {
					// NSEC based provider, no hashes have been used
					guessed, wordlistSize = zonewalk.NsecZoneCoverage(config)
				} else {
					// NSEC3 based provider, uses SHA1 hashes
					guessed, wordlistSize = zonewalk.Nsec3ZoneReversing(config, salt, iterations)
				}
				wordlistData = append(wordlistData, fmt.Sprintf("%d", len(guessed)))
				fmt.Printf("\r%d names guessed for zone %s\n", len(guessed), zone)
			}

		}
		wordlistData[1] = fmt.Sprintf("%d", wordlistSize)
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

	// Write any buffered data
	w.Flush()

	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
}
