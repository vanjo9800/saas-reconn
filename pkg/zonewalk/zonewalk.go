package zonewalk

import (
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"saasreconn/pkg/cache"
	"saasreconn/pkg/tools"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const zoneScanDomainsBufferSize = 100
const zoneScanResultsBufferSize = 10

// Config is a class for configuration of the zone-walking module
type Config struct {
	MappingCache    bool
	GuessesCache    bool
	UpdateCache     bool
	Hashcat         bool
	Mode            int
	Nameservers     []string
	NameserverIndex int
	Parallel        int
	RateLimit       int
	Timeout         int
	Verbose         int
	Wordlist        string
	Zone            string
}

// Only one thread can use the random subdomain generator at once as the random implementation is not concurrent
var randomLock sync.Mutex
var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomStringWithCharset(maxLength int, charset string) string {
	var result strings.Builder

	randomLock.Lock()
	length := seededRand.Intn(maxLength)
	for i := 0; i < length; i++ {
		index := seededRand.Intn(len(charset))
		result.WriteByte(charset[index])
	}
	randomLock.Unlock()

	return result.String()
}

func cleanHash(hash string) string {
	hash = strings.TrimSuffix(hash, ".")
	return hash
}

func DetectDNSSECType(config Config, nameserver string) (recordType string, salt string, iterations int) {

	randomPrefix := "saas-reconn"
	response := tools.DnsSyncQuery(nameserver, config.Zone, fmt.Sprintf("%s.%s", randomPrefix, config.Zone), dns.TypeA, config.Verbose)

	if response == nil {
		return "", "", 0
	}

	for _, rr := range response.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {

			// Check for "black lies" (RFC4470)
			nextDomain := rr.(*dns.NSEC).NextDomain
			if strings.HasPrefix(nextDomain, "\000") {
				fmt.Printf("[%s:%s] DNS server appears to use NSEC \"black lies\"\n NSEC record:  %s -> %s\n", nameserver, config.Zone, rr.Header().Name, nextDomain)
			}
			return "nsec", "", 0
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			algorithm := int(rr.(*dns.NSEC3).Hash)
			if algorithm != 1 {
				log.Printf("[%s:%s] Unsupported NSEC3 hashing algorithm %d", nameserver, config.Zone, algorithm)
				continue
			}
			iterations = int(rr.(*dns.NSEC3).Iterations)
			salt = rr.(*dns.NSEC3).Salt

			// Check for "white lies" (RFC4471)
			headerHash := tools.ExtractHash(rr.(*dns.NSEC3).Header().Name, config.Zone)
			nextDomainHash := rr.(*dns.NSEC3).NextDomain
			if CoveredDistance(headerHash, nextDomainHash) == big.NewInt(2) {
				fmt.Printf("[%s:%s] DNS server appears to use \"white lies\"\n NSEC3 record:  %s -> %s\n", nameserver, config.Zone, headerHash, nextDomainHash)
			}

			// Check for "opt-out" flag
			if rr.(*dns.NSEC3).Flags == 1 {
				fmt.Printf("[%s:%s] DNS server has the \"opt-out\" flag set\n", nameserver, config.Zone)
			}

			return "nsec3", salt, iterations
		}
	}

	return "", "", 0
}

// AttemptWalk tests whether a particular zone supports DNSSEC and attempts zone-walking it
func AttemptWalk(config Config) (names []string, isDNSSEC bool) {
	// Mode 0 is just diagnosing nameservers
	// Mode 1 is NSEC zone-walking / NSEC3 zone-mapping + hash reversing
	// Mode 2 is just NSEC zone-walking / NSEC3 zone-mapping
	// Mode 3 is just NSEC zone-walking / NSEC3 hash reversing

	if len(config.Nameservers) == 0 {
		config.Nameservers = tools.GetNameservers(config.Zone)
	}

	if len(config.Nameservers) == 0 {
		log.Printf("No nameservers found for %s", config.Zone)
		return
	}

	dnssecType, salt, iterations := DetectDNSSECType(config, config.Nameservers[0])

	// Does not support DNSSEC
	if len(dnssecType) == 0 {
		return
	}

	if dnssecType == "nsec" {
		isDNSSEC = true
		if config.Mode == 0 {
			fmt.Printf("[%s] Detected an NSEC signed zone\n", config.Zone)
			return
		}
		log.Printf("[%s] Starting NSEC zone-walking...", config.Zone)
		names = append(names, NsecZoneWalking(config)...)
	} else if dnssecType == "nsec3" {
		isDNSSEC = true
		if config.Mode == 0 {
			fmt.Printf("[%s] Detected an NSEC3 signed zone - salt `%s` with  %d iterations\n", config.Zone, salt, iterations)
			return
		}
		if config.Mode != 3 {
			log.Printf("[%s] Starting NSEC3 zone-enumeration (salt `%s` and %d iterations)", config.Zone, salt, iterations)
			Nsec3ZoneEnumeration(config, salt, iterations)
		}
		if config.Mode != 2 {
			log.Printf("[%s] Starting NSEC3 hash reversing (salt `%s` and %d iterations)", config.Zone, salt, iterations)
			reversedNames, _ := Nsec3ZoneReversing(config, salt, iterations)
			names = append(names, reversedNames...)
		}
	} else {
		log.Printf("[%s] Unexpected DNSSEC record %s", config.Zone, dnssecType)
	}

	return names, isDNSSEC
}

func fetchNsecCache(zone string) (cachedZoneWalk cache.CachedZoneWalk) {
	cachedResults := cache.NewCache()
	cachedZoneWalk, err := cachedResults.FetchCachedZoneWalk(zone, "", -1)
	if err != nil {
		cachedZoneWalk = cache.CachedZoneWalk{
			Salt:       "",
			Iterations: -1,
			Guessed:    map[string]string{},
		}
	}
	return cachedZoneWalk
}

func updateNsecCache(zone string, cachedZoneWalk cache.CachedZoneWalk) {
	cachedZoneWalk.Updated = time.Now()
	cachedResults := cache.NewCache()
	cachedResults.UpdateCachedZoneWalkData(zone, cachedZoneWalk)
}

func nsecRecordsWalk(config Config, finishWalk *bool, queries *tools.AtomicCounter, cachedZone *cache.CachedZoneWalk) (names []string) {
	queried := make(map[string]bool)
	start := "." + config.Zone
	nameserverIndex := 0
	for !*finishWalk {
		zoneBegin := strings.Index(start, ".")
		queryName := start[:zoneBegin] + "\\000." + start[zoneBegin+1:]
		if _, exists := queried[queryName]; exists {
			break
		}
		queries.Increment()
		response := tools.DnsSyncQuery(config.Nameservers[nameserverIndex], config.Zone, queryName, dns.TypeNSEC, config.Verbose)
		nameserverIndex = (nameserverIndex + 1) % len(config.Nameservers)
		queryBackOff := time.Now()

		if response == nil {
			continue
		}

		queried[queryName] = true
		start = start[zoneBegin+1:]

		// If we have got an exact answer
		for _, rr := range response.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC {
				start = rr.(*dns.NSEC).NextDomain
				if _, exists := cachedZone.Guessed[start]; !exists {
					if config.Verbose >= 5 {
						log.Printf("[%s] NSEC zone-walking: Found domain name %s", config.Zone, tools.CleanDomainName(start))
					}
					names = append(names, tools.CleanDomainName(start))
				}
				start = "." + start
				break
			}
		}

		if start == config.Zone {
			break
		}
		if config.RateLimit > 0 {
			time.Sleep(time.Second/time.Duration(config.RateLimit) - time.Since(queryBackOff))
		} else {
			if config.RateLimit == 0 {
				// Need to back-off for at least a second to not overload DNS client
				time.Sleep(time.Millisecond - time.Since(queryBackOff))
			}
		}
	}

	return names
}

func NsecZoneWalking(config Config) (names []string) {

	cachedZone := cache.CachedZoneWalk{
		Salt:       "",
		Iterations: -1,
		Guessed:    map[string]string{},
	}
	finishedZonewalking := false
	var queries tools.AtomicCounter

	if config.Timeout != 0 {
		startScan := time.Now()
		timeout := time.After(time.Duration(config.Timeout) * time.Second)
		tick := time.Tick(time.Second)
		go func() {
			names = nsecRecordsWalk(config, &finishedZonewalking, &queries, &cachedZone)
			finishedZonewalking = true
		}()

		for !finishedZonewalking {
			select {
			case <-timeout:
				finishedZonewalking = true
			case <-tick:
				if config.Verbose >= 3 {
					fmt.Printf("\r[%s] NSEC zone-walking: Found %d names, %d queries, elapsed time %s", config.Zone, len(names), queries.Read(), time.Since(startScan))
				}
			}
		}
	} else {
		names = nsecRecordsWalk(config, &finishedZonewalking, &queries, &cachedZone)
	}

	if config.UpdateCache {
		for _, name := range names {
			cachedZone.Guessed[strings.TrimSuffix(tools.CleanDomainName(name), fmt.Sprintf(".%s", config.Zone))] = "1"
		}
		updateNsecCache(config.Zone, cachedZone)
	}

	log.Printf("Names #2 %d", len(names))
	return names
}

func NsecZoneCoverage(config Config) (names []string, dictionarySize int) {

	cachedZoneMap := fetchNsecCache(config.Zone)

	dictionary := make(chan string)
	go BuildLocalDictionary(config.Wordlist, dictionary)
	dictionarySize = 0
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		dictionarySize++
		if _, ok := cachedZoneMap.Guessed[guess]; ok {
			names = append(names, guess)
		}
	}

	return tools.UniqueStrings(names), dictionarySize
}

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
			randomDomain := fmt.Sprintf("%s.%s.", randomStringWithCharset(63, tools.DomainNameCharset), config.Zone)
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
						Name: headerHash,
						Prev: headerHash,
						Next: nextOrderHash,
					})
				}
			}

			start = time.Now()
			for _, record := range fetchedHashes {
				zoneList.AddRecord(cleanHash(record.Prev), cleanHash(record.Next))
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
