package main

import (
	"encoding/base32"
	"encoding/hex"
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
	for key := range cachedZoneWalk {
		entry = key
		break
	}
	salt := strings.Split(entry, ":")[0]
	iterations, err := strconv.Atoi(strings.Split(entry, ":")[1])
	if err != nil {
		log.Fatalf("Could not get iterations: %s", err)
	}

	for _, name := range cachedZoneWalk[entry].List.Names {
		sha1Data, _ := base32.HexEncoding.DecodeString(name)
		hexName := hex.EncodeToString(sha1Data)
		fmt.Printf("$NSEC3$%d$%s$%s$%s.\n", iterations, salt, hexName, *zone)
	}
}
