package dns

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"regexp"
	"saasreconn/pkg/cache"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const domainNameCharset string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
const wordlistName string = "resources/namelist.txt"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomStringWithCharset(length int, charset string) string {
	var result strings.Builder
	for i := 0; i < length; i++ {
		result.WriteByte(charset[seededRand.Intn(len(charset))])
	}
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

	return "none", "", 0
}

// ZoneWalkAttempt tests whether a particular zone supports DNSSEC and attempts zone-walking it
func ZoneWalkAttempt(zone string, nameserver string, port int) (names []string) {

	// Default to system nameserver
	if len(nameserver) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			log.Printf("[%s] Error getting nameserver %s", zone, err)
			return names
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
		log.Printf("[%s] Not DNSSEC supported, skipping...", zone)
		return names
	}

	if dnssecType == "nsec" {
		log.Printf("[%s] Starting NSEC zone-walking...", zone)
		// Do NSEC zone-walking
		names = nsecZoneWalking(zone, nameserver)
	} else if dnssecType == "nsec3" {
		log.Printf("[%s] Starting NSEC3 zone-walking...", zone)
		// Do NSEC3 zone-walking
		hashes := nsec3ZoneScan(zone, nameserver, salt, iterations)

		cachedResults := cache.NewCache()
		cachedZoneWalk, err := cachedResults.FetchCachedZoneWalk(zone)
		// TODO: Add a time check + no-cache check
		if err != nil || (cachedZoneWalk.Iterations != iterations || cachedZoneWalk.Salt != salt) {
			cachedZoneWalk = cache.CachedZoneWalk{
				Salt:       salt,
				Iterations: iterations,
				Hashes:     []string{},
				Guessed:    map[string]string{},
				Updated:    time.Time{},
			}
		}
		cachedZoneWalk.Hashes = append(cachedZoneWalk.Hashes, hashes...)
		sort.Strings(cachedZoneWalk.Hashes)

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
		log.Printf("[%s] Does not support DNSSEC", zone)
	}

	return names
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

func nsec3ZoneScan(zone string, nameserver string, salt string, iterations int) (hashes []string) {
	hashTries := 200 //100000
	zoneRecord := CreateZoneList()

	for i := 0; i < hashTries; i++ {
		randomDomain := randomStringWithCharset(27, domainNameCharset)

		resp, _, err := dnssecQuery(nameserver, fmt.Sprintf("%s.%s", randomDomain, zone), dns.TypeA)
		if err != nil {
			log.Printf("[%s] Failed DNS lookup for %s.%s", zone, randomDomain, zone)
			continue
		}

		for _, rr := range resp.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC3 {
				algorithm := int(rr.(*dns.NSEC3).Hash)
				if algorithm != 1 {
					log.Printf("[%s] Unsupported NSEC3 hashing algorithm %d", zone, algorithm)
					return zoneRecord.HashedNames()
				}

				usedIterations := int(rr.(*dns.NSEC3).Iterations)
				usedSalt := rr.(*dns.NSEC3).Salt
				if usedIterations != iterations || usedSalt != salt {
					log.Printf("[%s] Zone changes its salt, or number of iterations, aborting...", zone)
					return zoneRecord.HashedNames()
				}

				headerHash := rr.(*dns.NSEC3).Header().Name
				headerHash = strings.ToUpper(strings.ReplaceAll(headerHash, "."+zone, ""))
				fmt.Printf("\rHash %d: Adding %s and %s", i, headerHash, rr.(*dns.NSEC3).NextDomain)
				zoneRecord.AddRecord(headerHash, rr.(*dns.NSEC3).NextDomain)
			}
		}
	}

	log.Printf("\n[%s] Found %d hashes with coverage %s", zone, zoneRecord.records, zoneRecord.Coverage())

	return zoneRecord.HashedNames()
}

func reverseNSEC3Hashes(hashes []string, zone string, salt string, iterations int) (mapping map[string]string) {

	mapping = make(map[string]string)

	fastLookup := make(map[string]bool)
	for _, hash := range hashes {
		fastLookup[hash] = true
	}

	_, err := os.Stat(wordlistName)
	if os.IsNotExist(err) {
		log.Printf("Could not read domain namelist %s", err)
		limit := 1000 //15000000 approx 63^4, so all 4 symbol hashes
		for i := 0; i < limit; i++ {
			randomGuess := randomStringWithCharset(4, domainNameCharset)
			nsec3 := dns.HashName(fmt.Sprintf("%s.%s", randomGuess, zone), dns.SHA1, uint16(iterations), salt)
			if _, ok := fastLookup[nsec3]; ok {
				mapping[nsec3] = randomGuess
			}
		}
		return mapping
	}

	file, err := os.Open(wordlistName)
	if err != nil {
		log.Printf("Error opening wordlist file %s", err)
		return mapping
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		guess := scanner.Text()
		nsec3 := dns.HashName(fmt.Sprintf("%s.%s", guess, zone), dns.SHA1, uint16(iterations), salt)
		if _, ok := fastLookup[nsec3]; ok {
			mapping[nsec3] = guess
			log.Printf("Guessed %s and %s", nsec3, guess)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading wordlist file %s", err)
	}

	return mapping
}

func dnssecQuery(nameserver string, queryName string, queryType uint16) (response *dns.Msg, rtt time.Duration, err error) {

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
