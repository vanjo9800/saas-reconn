package dns

import (
	"log"
	"math"
	"regexp"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var timeoutLogLock sync.Mutex
var timeoutLog map[string]bool = make(map[string]bool)

const failedRequestsThreshold = 10
const requestTimeout = 4 * time.Second
const timeoutWaitTime = 200 * time.Millisecond

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
			// log.Printf("[%s] Found nameserver %s for %s", domain, rr.(*dns.NS).Ns, domain)
		}
	}

	return nameservers
}

// SyncQuery is executing a synchronous DNS query waiting for a response, or returning a timeout
func SyncQuery(nameserver string, queryName string, queryType uint16, verbosity int) (response *dns.Msg) {
	responseChan := make(chan *dns.Msg)
	if verbosity >= 5 {
		log.Printf("[%s] Sending DNSSEC query for %s", nameserver, queryName)
	}
	AsyncQuery(nameserver, queryName, queryType, verbosity, responseChan)
	return <-responseChan
}

// AsyncQuery is executing an asynchronous DNS query writing the response to a channel passed as a parameter
func AsyncQuery(nameserver string, queryName string, queryType uint16, verbosity int, responseChannel chan<- *dns.Msg) {

	message := buildMessage()

	message.Question[0] = dns.Question{Name: dns.Fqdn(queryName), Qtype: queryType, Qclass: dns.ClassINET}

	client := new(dns.Client)
	client.Timeout = requestTimeout
	client.Net = "udp"
	client.UDPSize = 12320

	go sendDNSRequest(nameserver, queryName, message, client, verbosity, responseChannel)
}

func sendDNSRequest(nameserver string, queryName string, message *dns.Msg, client *dns.Client, verbosity int, responseChannel chan<- *dns.Msg) {
	// Send request
	response, rtt, dnsError := client.Exchange(message, nameserver)

	// Handle any errors
	if dnsError != nil {
		// Check if it is a timeout
		ioTimeoutMatch, err := regexp.MatchString(`i/o timeout`, dnsError.Error())
		if err == nil && ioTimeoutMatch {
			// Loop if another dns request is handling the back-off, or announce this thread is handling it
			for {
				timeoutLogLock.Lock()
				if val, ok := timeoutLog[nameserver]; val == false || !ok {
					timeoutLog[nameserver] = true
					timeoutLogLock.Unlock()
					defer func() {
						timeoutLogLock.Lock()
						timeoutLog[nameserver] = false
						timeoutLogLock.Unlock()
					}()
					break
				}
				timeoutLogLock.Unlock()
				time.Sleep(timeoutWaitTime)
			}

			// Exponential back-off
			failedRequests := 0
			for err == nil && ioTimeoutMatch {
				failedRequests++
				if failedRequests > failedRequestsThreshold {
					log.Printf("[%s] Too many timeouts, aborting request", queryName)
					return
				}
				if verbosity >= 5 {
					log.Printf("[%s] DNS request timeout, backing off after %d retries", queryName, failedRequests)
				}
				time.Sleep(rtt * time.Duration(math.Exp2(float64(failedRequests-1))))
				response, rtt, err = client.Exchange(message, nameserver)
				if err == nil {
					break
				}
				ioTimeoutMatch, err = regexp.MatchString(`i/o timeout`, err.Error())
			}
		} else {
			log.Printf("[%s] Unknown error type %s", queryName, dnsError)
			return
		}
	}

	if response.Truncated {
		if client.Net == "udp" {
			log.Printf("[%s] Truncated response, trying TCP", queryName)
			client.Net = "tcp"
			sendDNSRequest(nameserver, queryName, message, client, verbosity, responseChannel)
		} else {
			log.Printf("[%s] Already using TCP, could not parse response", queryName)
		}
		return
	}

	if response.Id != message.Id {
		log.Printf("[%s] ID mismatch", queryName)
		return
	}

	responseChannel <- response
}
