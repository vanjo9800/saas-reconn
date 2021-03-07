package dns

import (
	"log"
	"math"
	"regexp"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var timeoutGroup sync.WaitGroup

var failedRequests int

const failedRequestsThreshold = 10
const requestTimeout = 4 * time.Second

func buildMessage() (message *dns.Msg) {

	message = &dns.Msg{
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

	return message
}

// GetNameservers returns an list witht the nameservers for a domain name
func GetNameservers(domain string) (nameservers []string) {
	response := SyncQuery("8.8.8.8:53", domain, dns.TypeNS, 2)

	if response == nil {
		log.Printf("[%s] No nameservers response for %s", domain, domain)
		return nameservers
	}

	for _, rr := range response.Answer {
		if rr.Header().Rrtype == dns.TypeNS {
			nameservers = append(nameservers, rr.(*dns.NS).Ns)
			log.Printf("[%s] Found nameserver %s for %s", domain, rr.(*dns.NS).Ns, domain)
		}
	}

	return nameservers
}

// SyncQuery is executing a synchronous DNS query waiting for a response, or returning a timeout
func SyncQuery(nameserver string, queryName string, queryType uint16, verbosity int) (response *dns.Msg) {
	responseChan := make(chan *dns.Msg, 1)
	AsyncQuery(nameserver, queryName, queryType, verbosity, responseChan)

	select {
	case val := <-responseChan:
		return val
	case <-time.After(requestTimeout):
		log.Printf("[%s] Synchronous DNS query for %s to %s timed out", queryName, queryName, nameserver)
		return nil
	}
}

// AsyncQuery is executing an asynchronous DNS query writing the response to a channel passed as a parameter
func AsyncQuery(nameserver string, queryName string, queryType uint16, verbosity int, responseChannel chan<- *dns.Msg) {

	message := buildMessage()

	message.Question[0] = dns.Question{Name: dns.Fqdn(queryName), Qtype: queryType, Qclass: dns.ClassINET}

	client := new(dns.Client)
	client.Timeout = requestTimeout
	client.Net = "udp"
	client.UDPSize = 12320

	go func() {
		timeoutGroup.Wait()
		hadTimeout := false
		for {
			response, rtt, err := client.Exchange(message, nameserver)

			if err != nil {
				if !hadTimeout {
					timeoutGroup.Wait()
				}
				ioTimeoutMatch, err := regexp.MatchString(`i/o timeout`, err.Error())
				if err == nil && ioTimeoutMatch {
					if !hadTimeout {
						hadTimeout = true
						timeoutGroup.Add(1)
					}
					defer timeoutGroup.Done()
					failedRequests++
					if failedRequests > failedRequestsThreshold {
						log.Printf("[%s] Too many timeouts, aborting request", queryName)
						return
					}
					if verbosity >= 5 {
						log.Printf("[%s] DNS request timeout, backing off after %d retries", queryName, failedRequests)
					}
					time.Sleep(rtt * time.Duration(math.Exp2(float64(failedRequests-1))))
					continue
				} else {
					log.Printf("[%s] Unknown error type %s", queryName, err)
					return
				}
			}
			failedRequests = 0

			if response.Truncated {
				log.Printf("[%s] Truncated response, parsing not supported yet", queryName)
				return
			}

			if response.Id != message.Id {
				log.Printf("[%s] ID mismatch", queryName)
				return
			}

			responseChannel <- response
			return
		}
	}()
}
