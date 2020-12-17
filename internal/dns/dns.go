package dns

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/fatih/color"
	"github.com/miekg/dns"
)

type dnsArgs struct {
	Blacklist     stringset.Set
	Domains       stringset.Set
	MaxDNSQueries int
	Names         stringset.Set
	RecordTypes   stringset.Set
	Resolvers     stringset.Set
	Timeout       int
	Options       struct {
		DemoMode            bool
		IPs                 bool
		IPv4                bool
		IPv6                bool
		MonitorResolverRate bool
		Verbose             bool
	}
	Filepaths struct {
		AllFilePrefix string
		Blacklist     string
		ConfigFile    string
		Directory     string
		Domains       format.ParseStrings
		JSONOutput    string
		LogFile       string
		Names         format.ParseStrings
		Resolvers     format.ParseStrings
		TermOut       string
	}
}

func RunDNSCommand(domain string) {
	args := dnsArgs{
		Blacklist:   stringset.New(),
		Domains:     stringset.New(domain),
		Names:       stringset.New(),
		RecordTypes: stringset.New(),
		Resolvers:   stringset.New(),
	}
	dnsCommand := flag.NewFlagSet("dns", flag.ContinueOnError)

	dnsBuf := new(bytes.Buffer)
	dnsCommand.SetOutput(dnsBuf)

	cfg := config.NewConfig()
	cfg.Verbose = true
	cfg.Active = true
	cfg.Log = log.New(os.Stderr, "DNS info: ", log.Ldate|log.Ltime|log.Lshortfile)
	cfg.Timeout = 1
	cfg.ProvidedNames = append(cfg.ProvidedNames, domain)

	// Override configuration file settings with command-line arguments
	if err := cfg.UpdateConfig(args); err != nil {
		log.Fatal("Configuration error: " + err.Error())
	}

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		log.Fatal("Another error: " + err.Error())
	}

	log.Println("Performing Resolutions")
	performResolutions(cfg, sys)
}

func performResolutions(cfg *config.Config, sys systems.System) {
	done := make(chan struct{})
	active := make(chan struct{}, 1000000)
	bus := eventbus.NewEventBus()
	// answers := make(chan *requests.DNSRequest, 100000)

	// Setup the context used throughout the resolutions
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)
	ctx = context.WithValue(ctx, requests.ContextConfig, cfg)

	if cfg.Timeout > 0 {
		time.AfterFunc(time.Duration(cfg.Timeout)*time.Minute, func() {
			close(done)
		})
	}

	activeFunc := func(s string) { active <- struct{}{} }
	resolvFunc := func(t time.Time, rcode int) { active <- struct{}{} }
	bus.Subscribe(requests.SetActiveTopic, activeFunc)
	defer bus.Unsubscribe(requests.SetActiveTopic, activeFunc)
	bus.Subscribe(requests.ResolveCompleted, resolvFunc)
	defer bus.Unsubscribe(requests.ResolveCompleted, resolvFunc)

	log.Println("Before func()")
	// go func() {
	log.Println("In func()")

	dnsService := NewDNSService(sys)
	for _, name := range cfg.ProvidedNames {
		log.Println("Name " + name)
		select {
		case <-done:
			cancel()
			return
		default:
			if sys.PerformDNSQuery() == nil {
				log.Println("processDNSRequest")
				dnsService.OnDNSRequest(ctx, &requests.DNSRequest{Name: name, Domain: name})
				// go processDNSRequest(ctx, &requests.DNSRequest{Name: name}, cfg, sys, answers)
			}
		}
	}
	// // }()

	// processDNSAnswers(cfg, active, answers, done)
}

func processDNSRequest(ctx context.Context, req *requests.DNSRequest, cfg *config.Config, sys systems.System, c chan *requests.DNSRequest) {

	fmt.Println("Bam bam bam")
	fmt.Println("Req: ")
	fmt.Println(req)

	if req == nil || req.Name == "" {
		c <- nil
		return
	}

	req.Domain = sys.Pool().SubdomainToDomain(req.Name)
	if req.Domain == "" {
		c <- nil
		return
	}

	if cfg.Blacklisted(req.Name) || sys.Pool().GetWildcardType(ctx, req) == resolvers.WildcardTypeDynamic {
		c <- nil
		return
	}

	fmt.Println("Req: ")
	fmt.Println(req)

	var answers []requests.DNSAnswer
	for _, t := range cfg.RecordTypes {
		a, err := sys.Pool().Resolve(ctx, req.Name, t, resolvers.PriorityLow, resolvers.RetryPolicy)
		fmt.Println(a)
		fmt.Println(err)
		if err == nil {
			answers = append(answers, a...)
		}

		if t == "CNAME" && len(answers) > 0 {
			break
		}
	}
	req.Records = answers

	fmt.Println("Req: ")
	fmt.Println(req)

	if len(req.Records) == 0 || sys.Pool().MatchesWildcard(ctx, req) {
		c <- nil
		return
	}

	c <- req
}

func processDNSAnswers(cfg *config.Config,
	activeChan chan struct{}, answers chan *requests.DNSRequest, done chan struct{}) {
	first := true
	active := true

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	l := len(cfg.ProvidedNames)
loop:
	for i := 0; i < l; {
		select {
		case <-done:
			return
		case <-t.C:
			if first {
				continue
			} else if active {
				active = false
				continue
			}
			return
		case <-activeChan:
			active = true
		case req := <-answers:
			i++
			active = true
			first = false

			if req == nil || len(req.Records) == 0 {
				continue loop
			}

			// Print all the DNS records
			for _, rec := range req.Records {
				name := fmt.Sprintf("%-36s", req.Name)
				tstr := fmt.Sprintf("%-4s", typeToName(uint16(rec.Type)))

				if t := uint16(rec.Type); t == dns.TypeNS || t == dns.TypeSOA {
					pieces := strings.Split(rec.Data, ",")
					rec.Data = pieces[len(pieces)-1]
				}
				rec.Data = resolvers.RemoveLastDot(rec.Data)

				fmt.Fprintf(color.Output, "%s %s\t%s\n", name, tstr, rec.Data)
			}
		}
	}
}

// Obtain parameters from provided input files
func processDNSInputFiles(args *dnsArgs) error {
	if args.Filepaths.Blacklist != "" {
		list, err := config.GetListFromFile(args.Filepaths.Blacklist)
		if err != nil {
			return fmt.Errorf("Failed to parse the blacklist file: %v", err)
		}
		args.Blacklist.InsertMany(list...)
	}
	if len(args.Filepaths.Names) > 0 {
		for _, f := range args.Filepaths.Names {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the subdomain names file: %v", err)
			}

			args.Names.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Domains) > 0 {
		for _, f := range args.Filepaths.Domains {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the domain names file: %v", err)
			}

			args.Domains.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Resolvers) > 0 {
		for _, f := range args.Filepaths.Resolvers {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the esolver file: %v", err)
			}

			args.Resolvers.InsertMany(list...)
		}
	}
	return nil
}

// Setup the amass DNS settings
func (d dnsArgs) OverrideConfig(conf *config.Config) error {
	if d.Filepaths.Directory != "" {
		conf.Dir = d.Filepaths.Directory
	}
	if len(d.Names) > 0 {
		conf.ProvidedNames = d.Names.Slice()
	}
	if len(d.Blacklist) > 0 {
		conf.Blacklist = d.Blacklist.Slice()
	}
	if d.Timeout > 0 {
		conf.Timeout = d.Timeout
	}
	if d.Options.Verbose {
		conf.Verbose = true
	}
	if d.RecordTypes.Len() > 0 {
		conf.RecordTypes = d.RecordTypes.Slice()

		for i, qtype := range conf.RecordTypes {
			conf.RecordTypes[i] = strings.ToUpper(qtype)

			if conf.RecordTypes[i] == "CNAME" {
				tmp := conf.RecordTypes[0]

				conf.RecordTypes[0] = conf.RecordTypes[i]
				conf.RecordTypes[i] = tmp
			}
		}
	} else {
		conf.RecordTypes = []string{"A"}
	}
	if d.Resolvers.Len() > 0 {
		conf.SetResolvers(d.Resolvers.Slice()...)
	}
	if d.MaxDNSQueries > 0 {
		conf.MaxDNSQueries = d.MaxDNSQueries
	}
	if !d.Options.MonitorResolverRate {
		conf.MonitorResolverRate = false
	}

	// Attempt to add the provided domains to the configuration
	conf.AddDomains(d.Domains.Slice()...)
	return nil
}

func typeToName(qtype uint16) string {
	var name string

	switch qtype {
	case dns.TypeCNAME:
		name = "CNAME"
	case dns.TypeA:
		name = "A"
	case dns.TypeAAAA:
		name = "AAAA"
	case dns.TypePTR:
		name = "PTR"
	case dns.TypeNS:
		name = "NS"
	case dns.TypeMX:
		name = "MX"
	case dns.TypeTXT:
		name = "TXT"
	case dns.TypeSOA:
		name = "SOA"
	case dns.TypeSPF:
		name = "SPF"
	case dns.TypeSRV:
		name = "SRV"
	}

	return name
}
