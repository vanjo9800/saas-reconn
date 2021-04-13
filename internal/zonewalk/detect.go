package zonewalk

import (
	"fmt"
	"log"
	"math/big"
	"saasreconn/internal/tools"
	"strings"

	"github.com/miekg/dns"
)

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
