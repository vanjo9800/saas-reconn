package main

import (
	"flag"
	"fmt"
	"log"
	"saasreconn/internal/cache"
	"strconv"
	"strings"
)

func main() {
	zone := flag.String("zone", "", "select zone to convert")
	flag.Parse()

	if *zone == "" {
		log.Fatal("Please select zone to perform the conversion")
	}

	cache := cache.NewCache()
	cachedZoneWalk, err := cache.FetchZoneWalkForZone(*zone)
	if err != nil {
		log.Fatal(err)
	}
	if len(cachedZoneWalk) > 1 {
		log.Printf("Multiple entries for zone, picking the first one")
	}
	var entry string
	for key, _ := range cachedZoneWalk {
		entry = key
		break
	}
	salt := strings.Split(entry, ":")[0]
	iterations, err := strconv.Atoi(strings.Split(entry, ":")[1])
	if err != nil {
		log.Fatalf("Could not get iterations: %s", err)
	}

	fmt.Println(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
	fmt.Printf(";                                zone: %s.                                      \n", *zone)
	fmt.Println(";                                List of NSEC3 RRs                              ")
	fmt.Println(";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
	for index, name := range cachedZoneWalk[entry].List.Names {
		if cachedZoneWalk[entry].List.Next[index] != "" {
			fmt.Printf("%s.%s.\t86400\tIN\tNSEC3 1 0 %d %s %s\tA\n", strings.ToLower(name), *zone, iterations, salt, strings.ToLower(cachedZoneWalk[entry].List.Next[index]))
		}
	}
	fmt.Printf("; number of records = %d\n", len(cachedZoneWalk[entry].List.Names))
	fmt.Println()
	fmt.Printf(";; statistics\n; tested_hashes = 256\n; queries = 12\n")
}
