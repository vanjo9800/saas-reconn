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
	"time"

	"github.com/miekg/dns"
)

const domainNameCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

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
			}
			iterations = int(rr.(*dns.NSEC3).Iterations)
			salt = rr.(*dns.NSEC3).Salt
			log.Printf("[%s] Unsupported NSEC3PARAM record %d, %s", zone, iterations, salt)
			return "nsec3", salt, iterations
		}
	}

	return "none", "", 0
}

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
		mapping := make(map[string]string) // reverseNSEC3Hashes(hashes)

		cachedResults := cache.NewCache()
		cachedZoneWalk, err := cachedResults.FetchCachedZoneWalk(zone)
		// TODO: Add a time check
		if err != nil || (cachedZoneWalk.Iterations != iterations || cachedZoneWalk.Salt != salt) {
			cachedResults.UpdateCachedZoneWalkData(zone,
				(cache.CachedZoneWalk{
					Updated:    time.Now(),
					Salt:       salt,
					Iterations: iterations,
					Hashes:     hashes,
					Guessed:    mapping,
				}))
			for _, v := range mapping {
				names = append(names, v)
			}
		} else {
			cachedZoneWalk.Hashes = append(cachedZoneWalk.Hashes, hashes...)
			sort.Strings(cachedZoneWalk.Hashes)

			for hash, guess := range mapping {
				cachedZoneWalk.Guessed[hash] = guess
			}
			for _, v := range cachedZoneWalk.Guessed {
				names = append(names, v)
			}

			cachedZoneWalk.Updated = time.Now()
			cachedResults.UpdateCachedZoneWalkData(zone, cachedZoneWalk)
		}
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
					return zoneRecord.Names()
				}

				used_iterations := int(rr.(*dns.NSEC3).Iterations)
				used_salt := rr.(*dns.NSEC3).Salt
				if used_iterations != iterations || used_salt != salt {
					log.Printf("[%s] Zone changes its salt, or number of iterations, aborting...", zone)
					return zoneRecord.Names()
				}

				headerHash := rr.(*dns.NSEC3).Header().Name
				headerHash = strings.ToUpper(strings.ReplaceAll(headerHash, "."+zone, ""))
				fmt.Printf("Hash %d: Adding %s and %s\r", i, headerHash, rr.(*dns.NSEC3).NextDomain)
				zoneRecord.AddRecord(headerHash, rr.(*dns.NSEC3).NextDomain)
			}
		}
	}

	return zoneRecord.Names()
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
