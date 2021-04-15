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
	fmt.Printf("domain %s\nsalt %s\niterations %d\n", *zone, salt, iterations)

	for index, name := range cachedZoneWalk[entry].List.Names {
		if cachedZoneWalk[entry].List.Next[index] != "" {
			fmt.Printf("nexthash %s %s\n", strings.ToLower(name), strings.ToLower(cachedZoneWalk[entry].List.Next[index]))
		}
	}
}
