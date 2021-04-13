package tools

import (
	"log"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const defaultNameserverPort = 53

// Timeout log
var dnsTimeoutLogLock sync.Mutex
var dnsTimeoutLog map[string]bool = make(map[string]bool)

// Connections overload flag
var dnsConnectionsOverload AtomicFlag = AtomicFlag{
	Flag: false,
}

// Failed requests threshold
const failedDnsRequestsThreshold = 10

// Timeouts
const dnsRequestTimeout = 4 * time.Second
const dnsTimeoutWaitTime = 200 * time.Millisecond
const dnsConnectionsWaitPoll = 200 * time.Millisecond

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
		parts = append(parts, strconv.Itoa(defaultNameserverPort))
	}
	return parts[0], parts[1]
}

// GetNameservers returns an list witht the nameservers for a domain name
func GetNameservers(domain string) (nameservers []string) {
	response := DnsSyncQuery("8.8.8.8:53", domain, domain, dns.TypeNS, 2)

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

func GetClientConn(nameserver string, connectionType string, verbosity int) (client *dns.Client, conn *dns.Conn) {
	client = new(dns.Client)
	client.Timeout = dnsRequestTimeout
	client.Net = connectionType
	client.UDPSize = 12320

	nameserver, port := cleanNameserver(nameserver)
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, port)
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + port
	}
	conn, err := client.Dial(nameserver)
	if err != nil {
		tooManyConnectionsMatch, tooManyConnectionsMatchErr := regexp.MatchString(`socket: too many open files`, err.Error())
		if tooManyConnectionsMatchErr == nil && tooManyConnectionsMatch {
			dnsConnectionsOverload.Toggle()

			defer func() {
				dnsConnectionsOverload.Toggle()
			}()

			// Exponential back-off
			failedRequests := 0
			for tooManyConnectionsMatchErr == nil && tooManyConnectionsMatch {
				failedRequests++
				if failedRequests > failedDnsRequestsThreshold {
					log.Printf("[%s] Too many failures to connect, aborting request", nameserver)
					return nil, nil
				}
				if verbosity >= 5 {
					log.Printf("[%s] Could not open DNS connection, backing off after %d retries", nameserver, failedRequests)
				}
				time.Sleep(100 * time.Millisecond * time.Duration(math.Exp2(float64(failedRequests-1))))
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
func DnsSyncQuery(nameserver string, zone string, queryName string, queryType uint16, verbosity int) (response *dns.Msg) {
	responseChan := make(chan *dns.Msg)
	if verbosity >= 5 {
		log.Printf("[%s] Sending DNSSEC query for %s", nameserver, queryName)
	}
	DnsAsyncQuery(nameserver, zone, queryName, queryType, verbosity, responseChan, func() {})
	return <-responseChan
}

// AsyncQuery is executing an asynchronous DNS query writing the response to a channel passed as a parameter
func DnsAsyncQuery(nameserver string, zone string, queryName string, queryType uint16, verbosity int, responseChannel chan<- *dns.Msg, onReturn func()) {

	message := buildMessage()

	message.Question[0] = dns.Question{Name: dns.Fqdn(queryName), Qtype: queryType, Qclass: dns.ClassINET}

	for {
		if !dnsConnectionsOverload.Read() {
			break
		}
		time.Sleep(dnsConnectionsWaitPoll)
	}

	client, conn := GetClientConn(nameserver, "udp", verbosity)
	if conn == nil {
		if verbosity >= 4 {
			log.Printf("[%s] Unable to establish connection to %s and send request", queryName, nameserver)
		}
		return
	}
	go sendDNSRequest(client, conn, message, queryName, zone, verbosity, responseChannel, onReturn)
}

func sendDNSRequest(client *dns.Client, conn *dns.Conn, message *dns.Msg, query string, zone string, verbosity int, responseChannel chan<- *dns.Msg, onReturn func()) {

	defer onReturn()

	// Send request
	response, rtt, dnsErr := client.ExchangeWithConn(message, conn)

	// Handle any errors
	if dnsErr != nil {
		// Check if it is a timeout
		ioTimeoutMatch, timeoutMatchErr := regexp.MatchString(`i/o timeout`, dnsErr.Error())
		if timeoutMatchErr == nil && ioTimeoutMatch {
			// Loop if another dns request is handling the back-off, or announce this thread is handling it
			for {
				dnsTimeoutLogLock.Lock()
				nameserverAndZone := conn.RemoteAddr().String() + ":" + zone
				if val, ok := dnsTimeoutLog[nameserverAndZone]; val == false || !ok {
					dnsTimeoutLog[nameserverAndZone] = true
					dnsTimeoutLogLock.Unlock()
					defer func(nameserverAndZone string) {
						dnsTimeoutLogLock.Lock()
						dnsTimeoutLog[nameserverAndZone] = false
						dnsTimeoutLogLock.Unlock()
					}(nameserverAndZone)
					break
				}
				dnsTimeoutLogLock.Unlock()
				time.Sleep(dnsTimeoutWaitTime)
			}

			// Exponential back-off
			failedRequests := 0
			for timeoutMatchErr == nil && ioTimeoutMatch {
				failedRequests++
				if failedRequests > failedDnsRequestsThreshold {
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
			tcpClient, tcpConn := GetClientConn(conn.RemoteAddr().String(), "tcp", verbosity)
			if tcpConn == nil {
				if verbosity >= 4 {
					log.Printf("[%s] Unable to establish TCP connection to %s and re-send request", query, conn.RemoteAddr().String())
				}
				return
			}
			sendDNSRequest(tcpClient, tcpConn, message, query, zone, verbosity, responseChannel, func() {})
		} else {
			log.Printf("[%s] Already using TCP, could not parse truncated response", query)
		}
		return
	}

	if response.Id != message.Id {
		log.Printf("[%s] ID mismatch", query)
		return
	}

	responseChannel <- response
}
