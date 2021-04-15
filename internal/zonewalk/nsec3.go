package zonewalk

import (
	"fmt"
	"log"
	"saasreconn/internal/cache"
	"saasreconn/internal/tools"
	"sort"
	"time"

	"github.com/miekg/dns"
)

const zoneScanDomainsBufferSize = 20
const zoneScanResultsBufferSize = 20

func fetchNsec3Cache(zone string, salt string, iterations int) (cachedZoneWalk cache.CachedZoneWalk) {
	cachedResults := cache.NewCache()
	cachedZoneWalk, err := cachedResults.FetchCachedZoneWalk(zone, salt, iterations)
	if err != nil {
		cachedZoneWalk = cache.CachedZoneWalk{
			Salt:       salt,
			Iterations: iterations,
			Hashes:     []string{},
			List: cache.CachedZoneList{
				Names: []string{},
				Prev:  []string{},
				Next:  []string{},
			},
			Guessed: map[string]string{},
		}
	}
	return cachedZoneWalk
}

func updateNsec3Cache(zone string, cachedZoneWalk cache.CachedZoneWalk) {
	cachedZoneWalk.Updated = time.Now()
	cachedResults := cache.NewCache()
	cachedResults.UpdateCachedZoneWalkData(zone, cachedZoneWalk)
}

func Nsec3ZoneEnumeration(config Config, salt string, iterations int) (hashesCount int, queriesCount int) {

	var cachedZoneMap cache.CachedZoneWalk
	if config.MappingCache {
		cachedZoneMap = fetchNsec3Cache(config.Zone, salt, iterations)
	}

	if config.Verbose >= 4 {
		fmt.Printf("[%s] Starting zone-enumeration (timeout %d)...\n", config.Zone, config.Timeout)
	}
	start := time.Now()

	initialHashCount := len(cachedZoneMap.Hashes)
	hashes, exportedList, queriesCount := nsec3ZoneScan(config, salt, iterations, &cachedZoneMap.List)
	cachedZoneMap.Hashes = tools.UniqueStrings(append(cachedZoneMap.Hashes, hashes...))
	cachedZoneMap.Salt = salt
	cachedZoneMap.Iterations = iterations
	cachedZoneMap.List = exportedList
	sort.Strings(cachedZoneMap.Hashes)

	elapsed := time.Since(start)
	if config.Verbose >= 4 {
		fmt.Printf("\n[%s] Finished zone-enumeration...\n", config.Zone)
	}
	if config.Verbose >= 3 {
		fmt.Printf("\n[%s] Found %d (%d new) hashes in %s\n", config.Zone, len(hashes), len(hashes)-initialHashCount, elapsed)
	}

	if config.UpdateCache {
		updateNsec3Cache(config.Zone, cachedZoneMap)
	}

	return len(hashes), queriesCount
}

func Nsec3ZoneReversing(config Config, salt string, iterations int) (names []string, dictionarySize int) {

	cachedZoneMap := fetchNsec3Cache(config.Zone, salt, iterations)
	if !config.GuessesCache {
		cachedZoneMap.Guessed = make(map[string]string)
	}

	if config.Verbose >= 3 {
		fmt.Printf("[%s] Starting hash reversing of %d hashes...\n", config.Zone, len(cachedZoneMap.Hashes))
	}
	var mapping map[string]string
	if config.Hashcat {
		if config.Verbose >= 3 {
			fmt.Printf("Using hashcat for hash reversing...\n")
		}
		exportLocation := ExportToHashcat(cachedZoneMap.Hashes, config.Zone, salt, iterations)
		mapping, dictionarySize = RunHashcat(config, exportLocation)
		CleanHashcatDir()
	} else {
		if config.Verbose >= 3 {
			fmt.Printf("Using built-in hash reversing...\n")
		}
		mapping, dictionarySize = localNSEC3HashReverse(config, salt, iterations, cachedZoneMap.Hashes)
	}

	for hash, guess := range mapping {
		cachedZoneMap.Guessed[hash] = guess
	}
	for _, prefix := range cachedZoneMap.Guessed {
		names = append(names, fmt.Sprintf("%s.%s", prefix, config.Zone))
	}
	if config.Verbose >= 3 {
		fmt.Printf("[%s] Finished hash reversing...\n", config.Zone)
	}

	if config.UpdateCache {
		updateNsec3Cache(config.Zone, cachedZoneMap)
	}

	return names, dictionarySize
}

func nsec3ZoneScan(config Config, salt string, iterations int, cachedZoneList *cache.CachedZoneList) (hashes []string, treeJSON cache.CachedZoneList, queriesCount int) {
	zoneList := CreateZoneList(*cachedZoneList)

	finishedMapping := false
	pendingLookups := make(chan string, zoneScanDomainsBufferSize)
	pendingResults := make(chan *dns.Msg, zoneScanResultsBufferSize)

	startScan := time.Now()
	timeout := time.After(time.Duration(config.Timeout) * time.Second)
	tick := time.Tick(time.Second)
	lastCount := zoneList.records()

	// Start domain names generator / pre-hashing
	go func() {
		for !finishedMapping {
			// Domain names should be 63 symbols or less (RFC1035)
			randomDomain := fmt.Sprintf("%s.%s.", tools.RandomStringWithCharset(63, tools.DomainNameCharset), config.Zone)
			randomDomainHash := dns.HashName(randomDomain, dns.SHA1, uint16(iterations), salt)

			// Do not peform a DNS query if we already have connected the zone map for the new domain
			if zoneList.Covered(randomDomainHash) {
				continue
			}

			pendingLookups <- randomDomain
		}
		close(pendingLookups)
	}()

	queriesCount = 0
	hashDelayAccum, hashDelayCount := 0, 0
	dnsReqLimitAccum, dnsReqLimitCount := 0, 0
	dnsRequestsOnRoute := make(chan bool, config.Parallel)
	go func() {
		nameserverIndex := 0
		for !finishedMapping {
			start := time.Now()
			domainLookup, more := <-pendingLookups
			hashDelayAccum += int(time.Since(start).Milliseconds())
			hashDelayCount++
			if !more {
				break
			}

			// Limit number of parallel DNS queries
			start = time.Now()
			dnsRequestsOnRoute <- true
			dnsReqLimitAccum += int(time.Since(start).Milliseconds())
			dnsReqLimitCount++

			tools.DnsAsyncQuery(config.Nameservers[nameserverIndex], config.Zone, domainLookup, dns.TypeA, config.Verbose, pendingResults, func() { <-dnsRequestsOnRoute })
			nameserverIndex = (nameserverIndex + 1) % len(config.Nameservers)
			queriesCount++
			if config.RateLimit > 0 {
				time.Sleep(time.Second / time.Duration(config.RateLimit))
			} else {
				// Need to back-off for at least a second to not overload DNS client
				if config.RateLimit == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}
	}()

	dnsQueryDelayAccum, dnsQueryDelayCount := 0, 0
	hashAddAccum, hashAddCount := 0, 0
	go func() {
		for !finishedMapping {
			start := time.Now()
			results := <-pendingResults
			dnsQueryDelayAccum += int(time.Since(start).Milliseconds())
			dnsQueryDelayCount++

			fetchedHashes := []ZoneRecord{}
			for _, rr := range results.Ns {
				if rr.Header().Rrtype == dns.TypeNSEC3 {
					algorithm := int(rr.(*dns.NSEC3).Hash)
					if algorithm != 1 {
						log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", config.Zone, algorithm)
						return
					}

					usedIterations := int(rr.(*dns.NSEC3).Iterations)
					usedSalt := rr.(*dns.NSEC3).Salt
					if usedIterations != iterations || usedSalt != salt {
						log.Printf("[%s] Zone changes its salt, or number of iterations, aborting...", config.Zone)
						return
					}

					headerHash := tools.ExtractHash(rr.(*dns.NSEC3).Header().Name, config.Zone)
					nextOrderHash := rr.(*dns.NSEC3).NextDomain

					closestHash := zoneList.Closest(headerHash)
					// Do not add hash if it is already in the database
					if closestHash.Name != "" && closestHash.Next == nextOrderHash {
						continue
					}
					fetchedHashes = append(fetchedHashes, ZoneRecord{
						Prev: headerHash,
						Next: nextOrderHash,
					})
				}
			}

			start = time.Now()
			for _, record := range fetchedHashes {
				zoneList.AddRecord(record.Prev, record.Next)
			}
			hashAddAccum += int(time.Since(start).Milliseconds())
			hashAddCount++
		}
	}()

	for {
		select {
		case <-timeout:
			finishedMapping = true
			return zoneList.HashedNames(), zoneList.ExportList(), queriesCount
		case <-tick:
			if config.Verbose >= 3 {
				// unQCoverage
				_, QCoverage := zoneList.Coverage()
				fmt.Printf("[%s] Found %d hashes with %d queries, speed %d/second, estimated zone size %s, elapsed time %s\r",
					config.Zone,
					zoneList.records(),
					queriesCount,
					2*(zoneList.records()-lastCount),
					// unQCoverage,
					QCoverage,
					time.Since(startScan),
				)
			}
			lastCount = zoneList.records()
			if config.Verbose >= 4 {
				log.Printf("\n[:%s] Average delays %.2fms for pre-hashing, %.2fms for dns queries, %.2fms for processing DNS response, %.2fms for adding to database\n",
					config.Zone,
					float64(hashDelayAccum)/float64(hashDelayCount),
					float64(dnsReqLimitAccum)/float64(dnsReqLimitCount),
					float64(dnsQueryDelayAccum)/float64(dnsQueryDelayCount),
					float64(hashAddAccum)/float64(hashAddCount))
			}
		}
	}
}

func localNSEC3HashReverse(config Config, salt string, iterations int, hashes []string) (mapping map[string]string, dictionarySize int) {

	mapping = make(map[string]string)

	fastLookup := make(map[string]bool)
	for _, hash := range hashes {
		fastLookup[hash] = true
	}

	dictionary := make(chan string)
	go BuildLocalDictionary(config.Wordlist, dictionary)
	dictionarySize = 0
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		dictionarySize++
		if config.Verbose >= 5 {
			fmt.Printf("\r exhausted %d possibilities", dictionarySize)
		}
		nsec3 := dns.HashName(fmt.Sprintf("%s.%s.", guess, config.Zone), dns.SHA1, uint16(iterations), salt)
		if _, ok := fastLookup[nsec3]; ok {
			mapping[nsec3] = guess
		}
	}

	if config.Verbose >= 2 {
		fmt.Printf("[%s] Zone reversing used dictionary of %d entries\n", config.Zone, dictionarySize)
	}

	return mapping, dictionarySize
}
