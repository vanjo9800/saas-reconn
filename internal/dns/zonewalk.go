package dns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	debug     bool
	port      int
	startfrom string
)

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

func detectDNSSECType(zone string, nameserver string) string {

	randomPrefix := "bzvdhelrad"

	resp, _, err := dnssecQuery(nameserver, fmt.Sprintf("%s.%s", randomPrefix, zone), dns.TypeA)
	if err != nil {
		log.Printf("[%s] Error in DNS check for %s.%s", zone, randomPrefix, zone)
		return ""
	}

	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			return "nsec"
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			return "nsec3"
		}
	}

	return "none"
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

	dnssecType := detectDNSSECType(zone, nameserver)

	if len(dnssecType) == 0 {
		log.Printf("[%s] Not DNSSEC supported, skipping...", zone)
		return names
	}

	if dnssecType == "nsec" {
		log.Printf("[%s] Starting NSEC zone-walking...", zone)
		// Do NSEC zone-walking
		names = nsecZoneWalking(zone, nameserver)
	} else {
		log.Printf("[%s] Starting NSEC3 zone-walking...", zone)
		// Do NSEC3 zone-walking
	}

	return names
}

func nsecZoneWalking(zone string, nameserver string) (names []string) {

	seen := make(map[string]int)
	start := "." + zone
	for {
		zoneBegin := strings.Index(start, ".")
		queryName := start[:zoneBegin] + "\\000." + start[zoneBegin+1:]
		resp, _, err := dnssecQuery(nameserver, queryName, dns.TypeNSEC)

		if err != nil {
			log.Printf("[%s] NSEC zone-walk: Unexpected error %s", zone, err)
			return names
		}
		start = start[zoneBegin+1:]

		// If we have got an exact answer
		for _, rr := range resp.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC {
				start = rr.(*dns.NSEC).NextDomain
				if seen[start] == 1 {
					continue
				}
				names = append(names, strings.ReplaceAll(start, "*.", ""))
				seen[start] = 1
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
