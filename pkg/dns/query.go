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

var connectionsOverloadLock sync.Mutex
var connectionsOverload bool

const failedRequestsThreshold = 10
const requestTimeout = 4 * time.Second
const timeoutWaitTime = 200 * time.Millisecond
const connectionsWaitPoll = 200 * time.Millisecond

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
		}
	}

	return nameservers
}

func GetClientConn(nameserver string, verbosity int) (client *dns.Client, conn *dns.Conn) {
	client = new(dns.Client)
	client.Timeout = requestTimeout
	client.Net = "udp"
	client.UDPSize = 12320

	conn, err := client.Dial(nameserver)
	if err != nil {
		tooManyConnectionsMatch, tooManyConnectionsMatchErr := regexp.MatchString(`socket: too many open files`, err.Error())
		if tooManyConnectionsMatchErr == nil && tooManyConnectionsMatch {
			connectionsOverloadLock.Lock()
			connectionsOverload = true
			connectionsOverloadLock.Unlock()

			defer func() {
				connectionsOverloadLock.Lock()
				connectionsOverload = false
				connectionsOverloadLock.Unlock()
			}()

			// Exponential back-off
			failedRequests := 0
			for tooManyConnectionsMatchErr == nil && tooManyConnectionsMatch {
				failedRequests++
				if failedRequests > failedRequestsThreshold {
					log.Printf("[%s] Too many failures to connect, aborting request", nameserver)
					return nil, nil
				}
				if verbosity >= 5 {
					log.Printf("[%s] Could not open DNS connection, backing off after %d retries", nameserver, failedRequests)
				}
				time.Sleep(time.Millisecond * time.Duration(math.Exp2(float64(failedRequests-1))))
				conn, err = client.Dial(nameserver)
				if err == nil {
					log.Printf("[%s] Successfully connected after back-off", nameserver)
					return client, conn
				}
				tooManyConnectionsMatch, tooManyConnectionsMatchErr = regexp.MatchString(`socket: too many open files`, err.Error())
			}

		} else {
			log.Printf("[%s] Could not connect to host (unknown error): %s", nameserver, err)
			return nil, nil
		}
	}

	return client, conn
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

	for {
		connectionsOverloadLock.Lock()
		isOverloaded := connectionsOverload
		connectionsOverloadLock.Unlock()
		if !isOverloaded {
			break
		}
		time.Sleep(connectionsWaitPoll)
	}

	client, conn := GetClientConn(nameserver, verbosity)
	go sendDNSRequest(client, conn, message, queryName, verbosity, responseChannel)
}

func sendDNSRequest(client *dns.Client, conn *dns.Conn, message *dns.Msg, query string, verbosity int, responseChannel chan<- *dns.Msg) {

	// Send request
	response, rtt, dnsErr := client.ExchangeWithConn(message, conn)

	// Handle any errors
	if dnsErr != nil {
		// Check if it is a timeout
		ioTimeoutMatch, timeoutMatchErr := regexp.MatchString(`i/o timeout`, dnsErr.Error())
		if timeoutMatchErr == nil && ioTimeoutMatch {
			// Loop if another dns request is handling the back-off, or announce this thread is handling it
			for {
				timeoutLogLock.Lock()
				if val, ok := timeoutLog[conn.RemoteAddr().String()]; val == false || !ok {
					timeoutLog[conn.RemoteAddr().String()] = true
					timeoutLogLock.Unlock()
					defer func() {
						timeoutLogLock.Lock()
						timeoutLog[conn.RemoteAddr().String()] = false
						timeoutLogLock.Unlock()
					}()
					break
				}
				timeoutLogLock.Unlock()
				time.Sleep(timeoutWaitTime)
			}

			// Exponential back-off
			failedRequests := 0
			for timeoutMatchErr == nil && ioTimeoutMatch {
				failedRequests++
				if failedRequests > failedRequestsThreshold {
					log.Printf("[%s] Too many timeouts, aborting request", query)
					return
				}
				if verbosity >= 5 {
					log.Printf("[%s] DNS request timeout, backing off after %d retries", query, failedRequests)
				}
				time.Sleep(rtt * time.Duration(math.Exp2(float64(failedRequests-1))))
				response, rtt, dnsErr = client.ExchangeWithConn(message, conn)
				if dnsErr == nil {
					log.Printf("[%s] Successfully restored after back-off", query)
					break
				}
				ioTimeoutMatch, timeoutMatchErr = regexp.MatchString(`i/o timeout`, dnsErr.Error())
			}
		} else {
			log.Printf("[%s] Unknown error type: %s", query, dnsErr)
			return
		}
	}

	if response.Truncated {
		if client.Net == "udp" {
			log.Printf("[%s] Truncated response, trying TCP", query)
			client.Net = "tcp"
			sendDNSRequest(client, conn, message, query, verbosity, responseChannel)
		} else {
			log.Printf("[%s] Already using TCP, could not parse response", query)
		}
		return
	}

	if response.Id != message.Id {
		log.Printf("[%s] ID mismatch", query)
		return
	}

	responseChannel <- response
}
