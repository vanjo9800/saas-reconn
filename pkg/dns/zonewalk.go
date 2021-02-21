package dns

import (
	"errors"
	"fmt"
	"log"
	"math"
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
)

const domainnameCharset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

var randMutex sync.Mutex
var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

var dnsFailedRequests int

const dnsFailedRequestsThreshold = 10
const defaultPort = 53

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
	if len(parts) == 1 {
		parts = append(parts, strconv.Itoa(defaultPort))
	}
	return parts[0], parts[1]
}

func detectDNSSECType(zone string, nameserver string) (recordType string, salt string, iterations int) {

	randomPrefix := "bzvdhelrad"

	resp, err := dnssecQuery(nameserver, fmt.Sprintf("%s.%s", randomPrefix, zone), dns.TypeA)
	if err != nil {
		log.Printf("[%s] Error in DNS check for %s.%s", zone, randomPrefix, zone)
		return "", "", 0
	}

	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			return "nsec", "", 0
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			algorithm := int(rr.(*dns.NSEC3).Hash)
			if algorithm != 1 {
				log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", zone, algorithm)
				continue
			}
			iterations = int(rr.(*dns.NSEC3).Iterations)
			salt = rr.(*dns.NSEC3).Salt
			return "nsec3", salt, iterations
		}
	}

	return "", "", 0
}

// ZoneWalkAttempt tests whether a particular zone supports DNSSEC and attempts zone-walking it
func ZoneWalkAttempt(zone string, nameserver string, threads int, timeout int, noCache bool, zoneWalkMode int, hashcat bool) (names []string, isDNSSEC bool) {

	// Default to system nameserver
	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			log.Printf("[%s] Error getting nameserver %s", zone, err)
			return names, false
		}
		nameserver = conf.Servers[0]
	}

	nameserver, port := cleanNameserver(nameserver)
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, port)
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + port
	}

	// Remove trailing dots from zone
	// TODO:: check
	reg, _ := regexp.Compile(`\.*$`)
	zone = reg.ReplaceAllString(zone, ".")

	dnssecType, salt, iterations := detectDNSSECType(zone, nameserver)

	// Does not support DNSSEC
	if len(dnssecType) == 0 {
		return names, false
	}

	// Zero the timeout counter
	dnsFailedRequests = 0
	if dnssecType == "nsec" {
		log.Printf("[%s:%s] Starting NSEC zone-walking...", nameserver, zone)
		if zoneWalkMode != 0 {
			names = nsecZoneWalking(zone, nameserver)
		}
	} else if dnssecType == "nsec3" {
		log.Printf("[%s:%s] Starting NSEC3 zone-walking...", nameserver, zone)

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

		if zoneWalkMode != 2 {
			fmt.Printf("Starting zone-scan...\n")
			start := time.Now()

			hashes, exportedList := nsec3ZoneScan(zone, nameserver, salt, iterations, threads, timeout, &cachedZoneWalk.List)
			cachedZoneWalk.Hashes = append(cachedZoneWalk.Hashes, hashes...)
			cachedZoneWalk.List = exportedList
			sort.Strings(cachedZoneWalk.Hashes)

			elapsed := time.Since(start)
			fmt.Printf("Finished zone-scan...\n")
			fmt.Printf("[%s] Found %d hashes in %s", zone, len(hashes), elapsed)
		}

		if zoneWalkMode != 1 {
			fmt.Printf("Starting hash reversing...\n")
			var mapping map[string]string
			if hashcat {
				exportLocation := ExportToHashcat(cachedZoneWalk.Hashes, zone, salt, iterations)
				mapping = RunHashcat(exportLocation)
				// CleanHashcatDir()
			} else {
				mapping = reverseNSEC3Hashes(cachedZoneWalk.Hashes, zone, salt, iterations)
			}

			for hash, guess := range mapping {
				cachedZoneWalk.Guessed[hash] = guess
			}
			for _, v := range cachedZoneWalk.Guessed {
				names = append(names, v)
			}
			fmt.Printf("Finished hash reversing...\n")
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
		resp, err := dnssecQuery(nameserver, queryName, dns.TypeNSEC)
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
	pendingResults := make(chan *dns.Msg, bufferSize)

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
						randomDomain := fmt.Sprintf("%s.%s", randomStringWithCharset(27, domainnameCharset), zone)
						randomDomainHash := dns.HashName(randomDomain, dns.SHA1, uint16(iterations), salt)

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
					resp, err := dnssecQuery(nameserver, domainLookup, dns.TypeA)
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
						if rr.Header().Rrtype == dns.TypeNSEC3 {
							algorithm := int(rr.(*dns.NSEC3).Hash)
							if algorithm != 1 {
								log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", zone, algorithm)
								return
							}

							usedIterations := int(rr.(*dns.NSEC3).Iterations)
							usedSalt := rr.(*dns.NSEC3).Salt
							if usedIterations != iterations || usedSalt != salt {
								log.Printf("[%s] Zone changes its salt, or number of iterations, aborting...", zone)
								return
							}

							headerHash := rr.(*dns.NSEC3).Header().Name
							headerHash = strings.ToUpper(strings.ReplaceAll(headerHash, "."+zone, ""))
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

	dictionary := make(chan string)
	go BuildLocalDictionary(dictionary)
	count := 0
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		count++
		nsec3 := dns.HashName(fmt.Sprintf("%s.%s", guess, zone), dns.SHA1, uint16(iterations), salt)
		if _, ok := fastLookup[nsec3]; ok {
			mapping[nsec3] = guess
		}
	}

	fmt.Printf("Dictionary of %d entries\n", count)

	return mapping
}

func dnssecQuery(nameserver string, queryName string, queryType uint16) (response *dns.Msg, err error) {

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

	for {
		var rtt time.Duration
		response, rtt, err = client.Exchange(message, nameserver)

		if err != nil {
			log.Printf("[%s] Error occurred: %s", queryName, err)
			ioTimeoutMatch, err := regexp.MatchString(`i/o timeout`, err.Error())
			if err == nil && ioTimeoutMatch {
				dnsFailedRequests++
				if dnsFailedRequests > dnsFailedRequestsThreshold {
					log.Printf("[%s] Too many timeouts, aborting request", queryName)
					return nil, err
				}
				log.Printf("[%s] DNS request timeout, backing off after %d retries", queryName, dnsFailedRequests)
				time.Sleep(rtt * time.Duration(math.Exp2(float64(dnsFailedRequests-1))))
				continue
			} else {
				log.Printf("[%s] Unknown error type %s", queryName, err)
				return nil, err
			}
		}
		dnsFailedRequests = 0

		if response.Truncated {
			log.Printf("[%s] Truncated response, parsing not supported yet", queryName)
			return
		}

		if response.Id != message.Id {
			log.Printf("[%s] ID mismatch", queryName)
			return response, errors.New("Id mismatch")
		}

		return response, err
	}
}
