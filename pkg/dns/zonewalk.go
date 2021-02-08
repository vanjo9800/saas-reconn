package dns

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"regexp"
	"saasreconn/pkg/cache"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	dnslib "github.com/miekg/dns"
)

const domainNameCharset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

var randMutex sync.Mutex
var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomStringWithCharset(length int, charset string) string {
	var result strings.Builder

	randMutex.Lock()
	for i := 0; i < length; i++ {
		index := seededRand.Intn(len(charset))
		result.WriteByte(charset[index])
	}
	randMutex.Unlock()

	return result.String()
}

func cleanNameserver(nameserver string) string {
	// Starting with @
	if nameserver[0] == '@' {
		nameserver = nameserver[1:]
	}

	// Surrounded by []
	if nameserver[0] == '[' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}

	return nameserver
}

func detectDNSSECType(zone string, nameserver string) (recordType string, salt string, iterations int) {

	randomPrefix := "bzvdhelrad"

	resp, _, err := dnssecQuery(nameserver, fmt.Sprintf("%s.%s", randomPrefix, zone), dns.TypeA)
	if err != nil {
		log.Printf("[%s] Error in DNS check for %s.%s", zone, randomPrefix, zone)
		return "", "", 0
	}

	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dnslib.TypeNSEC {
			return "nsec", "", 0
		}
		if rr.Header().Rrtype == dnslib.TypeNSEC3 {
			algorithm := int(rr.(*dnslib.NSEC3).Hash)
			if algorithm != 1 {
				log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", zone, algorithm)
				continue
			}
			iterations = int(rr.(*dnslib.NSEC3).Iterations)
			salt = rr.(*dnslib.NSEC3).Salt
			return "nsec3", salt, iterations
		}
	}

	return "", "", 0
}

// ZoneWalkAttempt tests whether a particular zone supports DNSSEC and attempts zone-walking it
func ZoneWalkAttempt(zone string, nameserver string, port int, threads int, timeout int, noCache bool) (names []string, isDNSSEC bool) {

	// Default to system nameserver
	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			log.Printf("[%s] Error getting nameserver %s", zone, err)
			return names, false
		}
		nameserver = conf.Servers[0]
	}

	nameserver = cleanNameserver(nameserver)
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(port))
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(port)
	}

	// Remove trailing dots from zone
	reg, _ := regexp.Compile(`\.*$`)
	zone = reg.ReplaceAllString(zone, ".")

	dnssecType, salt, iterations := detectDNSSECType(zone, nameserver)

	if len(dnssecType) == 0 {
		return names, false
	}

	if dnssecType == "nsec" {
		log.Printf("[%s] Starting NSEC zone-walking...", zone)
		names = nsecZoneWalking(zone, nameserver)
	} else if dnssecType == "nsec3" {
		log.Printf("[%s] Starting NSEC3 zone-walking...", zone)

		cachedResults := cache.NewCache()
		cachedZoneWalk, err := cachedResults.FetchCachedZoneWalk(zone, salt, iterations)
		if err != nil || noCache {
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

		fmt.Printf("Starting zone-scan...\n")
		hashes, exportedList := nsec3ZoneScan(zone, nameserver, salt, iterations, threads, timeout, &cachedZoneWalk.List)
		cachedZoneWalk.Hashes = append(cachedZoneWalk.Hashes, hashes...)
		sort.Strings(cachedZoneWalk.Hashes)
		fmt.Printf("Finished zone-scan...\n")

		cachedZoneWalk.List = exportedList
		mapping := reverseNSEC3Hashes(hashes, zone, salt, iterations)

		for hash, guess := range mapping {
			cachedZoneWalk.Guessed[hash] = guess
		}
		for _, v := range cachedZoneWalk.Guessed {
			names = append(names, v)
		}

		cachedZoneWalk.Updated = time.Now()
		cachedResults.UpdateCachedZoneWalkData(zone, cachedZoneWalk)
	} else {
		log.Printf("[%s] Unexpected DNSSEC record %s", zone, dnssecType)
	}

	return names, true
}

func nsecZoneWalking(zone string, nameserver string) (names []string) {

	queried := make(map[string]bool)
	added := make(map[string]bool)
	start := "." + zone
	for {
		zoneBegin := strings.Index(start, ".")
		queryName := start[:zoneBegin] + "\\000." + start[zoneBegin+1:]
		if _, exists := queried[queryName]; exists {
			break
		}
		resp, _, err := dnssecQuery(nameserver, queryName, dns.TypeNSEC)
		queried[queryName] = true

		if err != nil {
			log.Printf("[%s] NSEC zone-walk: Unexpected error %s", zone, err)
			return names
		}
		start = start[zoneBegin+1:]

		// If we have got an exact answer
		for _, rr := range resp.Ns {
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

		if start == zone {
			break
		}
	}

	return names
}

func nsec3ZoneScan(zone string, nameserver string, salt string, iterations int, threads int, scanTimeout int, cachedZoneList *cache.CachedZoneList) (hashes []string, treeJSON cache.CachedZoneList) {
	batchSize := 100
	bufferSize := 10

	zoneList := CreateZoneList(*cachedZoneList)

	accumulatedHashes := make(chan []ZoneRecord, bufferSize)
	pendingLookups := make(chan string, batchSize)
	pendingResults := make(chan *dnslib.Msg, bufferSize)

	fmt.Printf("[%s] Starting zone enumeration (timeout %d)\n", zone, scanTimeout)
	concurrencyHashes := make(chan bool, threads)
	concurrencyLookups := make(chan bool, threads)
	concurrencyUpdates := make(chan bool, threads)
	for i := 0; i < threads; i++ {
		concurrencyHashes <- true
		concurrencyLookups <- true
		concurrencyUpdates <- true
	}

	timeout := time.After(time.Duration(scanTimeout) * time.Second)
	tick := time.Tick(500 * time.Millisecond)
	lastCount := zoneList.records()
	for {
		go func() {
			for {
				<-concurrencyHashes
				go func(zone string) {
					for hashCount := 0; hashCount < batchSize; hashCount++ {
						// Generate a random subdomain name with 160 bits ot randomness
						// Our domain name alphabet consists of 63 symbols and 63^27 approx 2^160
						randomDomain := fmt.Sprintf("%s.%s", randomStringWithCharset(27, domainNameCharset), zone)
						randomDomainHash := dnslib.HashName(randomDomain, dnslib.SHA1, uint16(iterations), salt)

						closestHash := zoneList.Closest(randomDomainHash)
						// Do not peform a DNS query if we already have connected the zone map for the new domain
						if closestHash.Next != "" && closestHash.Next >= randomDomainHash {
							continue
						}

						pendingLookups <- randomDomain
					}
					concurrencyHashes <- true
				}(zone)
			}
		}()
		go func() {
			for {
				<-concurrencyLookups
				go func(nameserver string) {
					domainLookup := <-pendingLookups
					defer func() {
						concurrencyLookups <- true
					}()
					resp, _, err := dnssecQuery(nameserver, domainLookup, dnslib.TypeA)
					if err != nil {
						log.Printf("Failed DNS lookup for %s: %s", domainLookup, err)
						return
					}
					pendingResults <- resp
				}(nameserver)
			}
		}()
		go func() {
			for {
				<-concurrencyUpdates
				go func(zone string) {
					fetchedHashes := []ZoneRecord{}
					results := <-pendingResults
					defer func() {
						concurrencyUpdates <- true
					}()
					for _, rr := range results.Ns {
						if rr.Header().Rrtype == dnslib.TypeNSEC3 {
							algorithm := int(rr.(*dnslib.NSEC3).Hash)
							if algorithm != 1 {
								log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", zone, algorithm)
								return
							}

							usedIterations := int(rr.(*dnslib.NSEC3).Iterations)
							usedSalt := rr.(*dnslib.NSEC3).Salt
							if usedIterations != iterations || usedSalt != salt {
								log.Printf("[%s] Zone changes its salt, or number of iterations, aborting...", zone)
								return
							}

							headerHash := rr.(*dnslib.NSEC3).Header().Name
							headerHash = strings.ToUpper(strings.ReplaceAll(headerHash, "."+zone, ""))
							nextOrderHash := rr.(*dnslib.NSEC3).NextDomain

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
				}(zone)
			}
		}()

		select {
		case <-timeout:
			return zoneList.HashedNames(), zoneList.ExportList()
		case <-tick:
			fmt.Printf("[%s] Found %d hashes with coverage %s, speed %d/second\n", zone, zoneList.records(), zoneList.Coverage(), 2*(zoneList.records()-lastCount))
			lastCount = zoneList.records()
		default:
			batchRecords := <-accumulatedHashes
			for _, record := range batchRecords {
				zoneList.AddRecord(record.Prev, record.Next)
			}
		}
	}
}

func reverseNSEC3Hashes(hashes []string, zone string, salt string, iterations int) (mapping map[string]string) {

	mapping = make(map[string]string)

	fastLookup := make(map[string]bool)
	for _, hash := range hashes {
		fastLookup[hash] = true
	}

	// _, err := os.Stat(wordlistName)
	// if os.IsNotExist(err) {
	// 	log.Printf("Could not read domain namelist %s", err)
	// 	limit := 1000 //15000000 approx 63^4, so all 4 symbol hashes
	// 	for i := 0; i < limit; i++ {
	// 		randomGuess := randomStringWithCharset(4, domainNameCharset)
	// 		nsec3 := dns.HashName(fmt.Sprintf("%s.%s", randomGuess, zone), dns.SHA1, uint16(iterations), salt)
	// 		if _, ok := fastLookup[nsec3]; ok {
	// 			mapping[nsec3] = randomGuess
	// 		}
	// 	}
	// 	return mapping
	// }

	dictionary := make(chan string)
	go BuildDictionary(dictionary)
	count := 0
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		count++
		nsec3 := dnslib.HashName(fmt.Sprintf("%s.%s", guess, zone), dnslib.SHA1, uint16(iterations), salt)
		if _, ok := fastLookup[nsec3]; ok {
			mapping[nsec3] = guess
			log.Printf("Guessed %s and %s", nsec3, guess)
		}
	}

	fmt.Printf("Dictionary of %d entries\n", count)

	return mapping
}

func dnssecQuery(nameserver string, queryName string, queryType uint16) (response *dnslib.Msg, rtt time.Duration, err error) {

	message := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			AuthenticatedData: false,
			Authoritative:     false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	message.Id = dns.Id()

	options := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	options.SetDo()
	options.SetUDPSize(dns.DefaultMsgSize)

	message.Extra = append(message.Extra, options)

	message.Question[0] = dns.Question{Name: dns.Fqdn(queryName), Qtype: queryType, Qclass: dns.ClassINET}

	client := new(dns.Client)
	client.Timeout = 4000 * time.Millisecond
	client.Net = "udp"
	client.UDPSize = 12320
	response, rtt, err = client.Exchange(message, nameserver)

	if err != nil {
		log.Printf("[%s] Error occurred: %s", queryName, err)
		return
	}

	if response.Truncated {
		log.Printf("[%s] Truncated...", queryName)
		return
	}

	if response.Id != message.Id {
		log.Printf("[%s] ID mismatch", queryName)
		return response, rtt, errors.New("Id mismatch")
	}

	return response, rtt, err
}
