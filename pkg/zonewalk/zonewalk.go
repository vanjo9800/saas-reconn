package zonewalk

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"saasreconn/pkg/cache"
	"sort"
	"strconv"
	"strings"
	"time"

	dnsTools "saasreconn/pkg/dns"

	"github.com/miekg/dns"
)

const domainnameCharset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

const defaultPort = 53

// Sets an initial request rate (r/s)
var requestRate = 50

// Config is a class for configuration of the zone-walking module
type Config struct {
	Cache      bool
	Hashcat    bool
	Mode       int
	Nameserver string
	Threads    int
	Timeout    int
	Verbose    int
	Wordlist   string
	Zone       string
}

func randomStringWithCharset(length int, charset string) string {
	var result strings.Builder

	for i := 0; i < length; i++ {
		index := seededRand.Intn(len(charset))
		result.WriteByte(charset[index])
	}

	return result.String()
}

func cleanHash(hash string) string {
	hash = strings.TrimSuffix(hash, ".")
	return hash
}

func cleanNameserver(nameserver string) (string, string) {
	// Starting with @
	if nameserver[0] == '@' {
		nameserver = nameserver[1:]
	}

	// Surrounded by []
	if nameserver[0] == '[' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}

	parts := strings.Split(nameserver, ":")
	parts[0] = strings.TrimSuffix(parts[0], ".")
	if len(parts) == 1 {
		parts = append(parts, strconv.Itoa(defaultPort))
	}
	return parts[0], parts[1]
}

func detectDNSSECType(config Config) (recordType string, salt string, iterations int) {

	randomPrefix := "bzvdhelrad"
	response := dnsTools.SyncQuery(config.Nameserver, fmt.Sprintf("%s.%s", randomPrefix, config.Zone), dns.TypeA, config.Verbose)

	if response == nil {
		return "", "", 0
	}

	for _, rr := range response.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			return "nsec", "", 0
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			algorithm := int(rr.(*dns.NSEC3).Hash)
			if algorithm != 1 {
				log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", config.Zone, algorithm)
				continue
			}
			iterations = int(rr.(*dns.NSEC3).Iterations)
			salt = rr.(*dns.NSEC3).Salt
			return "nsec3", salt, iterations
		}
	}

	return "", "", 0
}

// AttemptWalk tests whether a particular zone supports DNSSEC and attempts zone-walking it
func AttemptWalk(config Config) (names []string, isDNSSEC bool) {

	nameserver, port := cleanNameserver(config.Nameserver)
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, port)
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + port
	}
	config.Nameserver = nameserver

	dnssecType, salt, iterations := detectDNSSECType(config)

	// Does not support DNSSEC
	if len(dnssecType) == 0 {
		return names, false
	}

	// Zero the timeout counter
	if dnssecType == "nsec" {
		log.Printf("[%s:%s] Starting NSEC zone-walking...", config.Nameserver, config.Zone)
		if config.Mode != 0 {
			names = NsecZoneWalking(config)
		}
	} else if dnssecType == "nsec3" {
		log.Printf("[%s:%s] Starting NSEC3 zone-walking...", config.Nameserver, config.Zone)

		if config.Mode != 0 {
			names = Nsec3ZoneWalking(config, salt, iterations)
		}
	} else {
		log.Printf("[%s] Unexpected DNSSEC record %s", config.Zone, dnssecType)
	}

	return names, true
}

func NsecZoneWalking(config Config) (names []string) {

	queried := make(map[string]bool)
	added := make(map[string]bool)
	start := "." + config.Zone
	for {
		zoneBegin := strings.Index(start, ".")
		queryName := start[:zoneBegin] + "\\000." + start[zoneBegin+1:]
		if _, exists := queried[queryName]; exists {
			break
		}
		response := dnsTools.SyncQuery(config.Nameserver, queryName, dns.TypeNSEC, config.Verbose)

		if response == nil {
			continue
		}

		queried[queryName] = true
		start = start[zoneBegin+1:]

		// If we have got an exact answer
		for _, rr := range response.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC {
				start = rr.(*dns.NSEC).NextDomain
				if _, exists := added[start]; !exists {
					names = append(names, strings.ReplaceAll(start, "*.", ""))
					added[start] = true
				}
				start = "." + start
				break
			}
		}

		if start == config.Zone {
			break
		}
	}

	return names
}

func Nsec3ZoneWalking(config Config, salt string, iterations int) (names []string) {

	var cachedZoneWalk cache.CachedZoneWalk
	if config.Cache {
		cachedResults := cache.NewCache()
		var err error
		cachedZoneWalk, err = cachedResults.FetchCachedZoneWalk(config.Zone, salt, iterations)
		if err != nil {
			cachedZoneWalk = cache.CachedZoneWalk{
				Salt:       salt,
				Iterations: iterations,
				Hashes:     []string{},
				Guessed:    map[string]string{},
				Updated:    time.Time{},
				List: cache.CachedZoneList{
					Names:        names,
					Prev:         []string{},
					Next:         []string{},
					ExpectedSize: "",
				},
			}
		}
	}

	if config.Mode != 3 {
		fmt.Printf("Starting zone-scan...\n")
		start := time.Now()

		hashes, exportedList := nsec3ZoneScan(config, salt, iterations, &cachedZoneWalk.List)
		cachedZoneWalk.Hashes = append(cachedZoneWalk.Hashes, hashes...)
		cachedZoneWalk.List = exportedList
		sort.Strings(cachedZoneWalk.Hashes)

		elapsed := time.Since(start)
		fmt.Printf("\nFinished zone-scan...\n")
		fmt.Printf("[%s] Found %d hashes in %s\n", config.Zone, len(hashes), elapsed)
	}

	if config.Mode != 2 {
		if config.Verbose >= 3 {
			fmt.Printf("Starting hash reversing...\n")
		}
		var mapping map[string]string
		if config.Hashcat {
			exportLocation := ExportToHashcat(cachedZoneWalk.Hashes, config.Zone, salt, iterations)
			mapping = RunHashcat(exportLocation)
			CleanHashcatDir()
		} else {
			mapping = reverseNSEC3Hashes(config, salt, iterations, cachedZoneWalk.Hashes)
		}

		for hash, guess := range mapping {
			cachedZoneWalk.Guessed[hash] = guess
		}
		for _, v := range cachedZoneWalk.Guessed {
			names = append(names, v)
		}
		if config.Verbose >= 3 {
			fmt.Printf("Finished hash reversing...\n")
		}
	}

	cachedZoneWalk.Updated = time.Now()
	if config.Cache {
		cachedResults := cache.NewCache()
		cachedResults.UpdateCachedZoneWalkData(config.Zone, cachedZoneWalk)
	}

	return names
}

func nsec3ZoneScan(config Config, salt string, iterations int, cachedZoneList *cache.CachedZoneList) (hashes []string, treeJSON cache.CachedZoneList) {
	batchSize := 100
	bufferSize := 10

	zoneList := CreateZoneList(*cachedZoneList)

	accumulatedHashes := make(chan []ZoneRecord, bufferSize)
	pendingLookups := make(chan string, batchSize)
	pendingResults := make(chan *dns.Msg, bufferSize)

	fmt.Printf("[%s] Starting zone enumeration (timeout %d)\n", config.Zone, config.Timeout)

	timeout := time.After(time.Duration(config.Timeout) * time.Second)
	tick := time.Tick(time.Second)
	lastCount := zoneList.records()

	// Start domain names generator / pre-hashing
	go func() {
		for {
			for hashCount := 0; hashCount < batchSize; hashCount++ {
				// Generate a random subdomain name with 160 bits ot randomness
				// Our domain name alphabet consists of 63 symbols and 63^27 approx 2^160
				randomDomain := fmt.Sprintf("%s.%s", randomStringWithCharset(27, domainnameCharset), config.Zone)
				randomDomainHash := dns.HashName(randomDomain, dns.SHA1, uint16(iterations), salt)

				closestHash := zoneList.Closest(randomDomainHash)
				// Do not peform a DNS query if we already have connected the zone map for the new domain
				if closestHash.Next != "" && closestHash.Next >= randomDomainHash {
					continue
				}

				pendingLookups <- randomDomain
			}
		}
	}()

	dnsQueriesCount := 0
	hashDelayAccum, hashDelayCount := 0, 0
	go func() {
		for {
			start := time.Now()
			// fmt.Printf("Stalled waiting for hashes %d- ", len(pendingLookups))
			domainLookup := <-pendingLookups
			// fmt.Printf("Finished waiting for hashes\n")
			hashDelayAccum += int(time.Since(start).Milliseconds())
			hashDelayCount++
			dnsQueriesCount++
			dnsTools.AsyncQuery(config.Nameserver, domainLookup, dns.TypeA, config.Verbose, pendingResults)
			time.Sleep(time.Second / time.Duration(requestRate))
		}
	}()

	dnsQueryDelayAccum, dnsQueryDelayCount := 0, 0
	go func() {
		for {
			fetchedHashes := []ZoneRecord{}
			start := time.Now()
			results := <-pendingResults
			dnsQueryDelayAccum += int(time.Since(start).Milliseconds())
			dnsQueryDelayCount++
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

					headerHash := rr.(*dns.NSEC3).Header().Name
					headerHash = strings.ToUpper(strings.ReplaceAll(headerHash, "."+config.Zone, ""))
					nextOrderHash := rr.(*dns.NSEC3).NextDomain

					closestHash := zoneList.Closest(headerHash)
					// Do not add hash if it is already in the database
					if closestHash.Next != "" && closestHash.Next == nextOrderHash {
						continue
					}
					fetchedHashes = append(fetchedHashes, ZoneRecord{
						Name: headerHash,
						Prev: headerHash,
						Next: nextOrderHash,
					})
				}
			}
			accumulatedHashes <- fetchedHashes
		}
	}()

	dnsRespProcessAccum, dnsRespProcessCount := 0, 0
	hashAddAccum, hashAddCount := 0, 0
	for {
		select {
		case <-timeout:
			return zoneList.HashedNames(), zoneList.ExportList()
		case <-tick:
			fmt.Printf("[%s] Found %d hashes with coverage %s, queries %d, speed %d/second\r", config.Zone, zoneList.records(), zoneList.Coverage(), dnsQueriesCount, 2*(zoneList.records()-lastCount))
			lastCount = zoneList.records()
			fmt.Printf("\nAverage delays %.2f for pre-hashing, %.2f for dns queries, %.2f for processing DNS response, %.2f for adding to database\n",
				float64(hashDelayAccum)/float64(hashDelayCount),
				float64(dnsQueryDelayAccum)/float64(dnsQueryDelayCount),
				float64(dnsRespProcessAccum)/float64(dnsRespProcessCount),
				float64(hashAddAccum)/float64(hashAddCount))
		default:
			start := time.Now()
			batchRecords := <-accumulatedHashes
			dnsRespProcessAccum += int(time.Since(start).Milliseconds())
			dnsRespProcessCount++

			start = time.Now()
			for _, record := range batchRecords {
				zoneList.AddRecord(cleanHash(record.Prev), cleanHash(record.Next))
			}
			hashAddAccum += int(time.Since(start).Milliseconds())
			hashAddCount++

		}
	}
}

func reverseNSEC3Hashes(config Config, salt string, iterations int, hashes []string) (mapping map[string]string) {

	mapping = make(map[string]string)

	fastLookup := make(map[string]bool)
	for _, hash := range hashes {
		fastLookup[hash] = true
	}

	dictionary := make(chan string)
	go BuildLocalDictionary(config.Wordlist, dictionary)
	count := 0
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		count++
		nsec3 := dns.HashName(fmt.Sprintf("%s.%s", guess, config.Zone), dns.SHA1, uint16(iterations), salt)
		if _, ok := fastLookup[nsec3]; ok {
			mapping[nsec3] = guess
		}
	}

	if config.Verbose >= 3 {
		fmt.Printf("Dictionary of %d entries\n", count)
	}

	return mapping
}
