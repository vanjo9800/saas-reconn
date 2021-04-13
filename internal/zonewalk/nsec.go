package zonewalk

import (
	"fmt"
	"log"
	"saasreconn/internal/cache"
	"saasreconn/internal/tools"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func fetchNsecCache(zone string) (cachedZoneWalk cache.CachedZoneWalk) {
	cachedResults := cache.NewCache()
	cachedZoneWalk, err := cachedResults.FetchCachedZoneWalk(zone, "", -1)
	if err != nil {
		cachedZoneWalk = cache.CachedZoneWalk{
			Salt:       "",
			Iterations: -1,
			Guessed:    map[string]string{},
		}
	}
	return cachedZoneWalk
}

func updateNsecCache(zone string, cachedZoneWalk cache.CachedZoneWalk) {
	cachedZoneWalk.Updated = time.Now()
	cachedResults := cache.NewCache()
	cachedResults.UpdateCachedZoneWalkData(zone, cachedZoneWalk)
}

func nsecRecordsWalk(config Config, finishWalk *bool, queries *tools.AtomicCounter, cachedZone *cache.CachedZoneWalk) (names []string) {
	queried := make(map[string]bool)
	start := "." + config.Zone
	nameserverIndex := 0
	for !*finishWalk {
		zoneBegin := strings.Index(start, ".")
		queryName := start[:zoneBegin] + "\\000." + start[zoneBegin+1:]
		if _, exists := queried[queryName]; exists {
			break
		}
		queries.Increment()
		response := tools.DnsSyncQuery(config.Nameservers[nameserverIndex], config.Zone, queryName, dns.TypeNSEC, config.Verbose)
		nameserverIndex = (nameserverIndex + 1) % len(config.Nameservers)
		queryBackOff := time.Now()

		if response == nil {
			continue
		}

		queried[queryName] = true
		start = start[zoneBegin+1:]

		// If we have got an exact answer
		for _, rr := range response.Ns {
			if rr.Header().Rrtype == dns.TypeNSEC {
				start = rr.(*dns.NSEC).NextDomain
				if _, exists := cachedZone.Guessed[start]; !exists {
					if config.Verbose >= 5 {
						log.Printf("[%s] NSEC zone-walking: Found domain name %s", config.Zone, tools.CleanDomainName(start))
					}
					names = append(names, tools.CleanDomainName(start))
				}
				start = "." + start
				break
			}
		}

		if start == config.Zone {
			break
		}
		if config.RateLimit > 0 {
			time.Sleep(time.Second/time.Duration(config.RateLimit) - time.Since(queryBackOff))
		} else {
			if config.RateLimit == 0 {
				// Need to back-off for at least a second to not overload DNS client
				time.Sleep(time.Millisecond - time.Since(queryBackOff))
			}
		}
	}

	return names
}

func NsecZoneWalking(config Config) (names []string) {

	cachedZone := cache.CachedZoneWalk{
		Salt:       "",
		Iterations: -1,
		Guessed:    map[string]string{},
	}
	finishedZonewalking := false
	var queries tools.AtomicCounter

	if config.Timeout != 0 {
		startScan := time.Now()
		timeout := time.After(time.Duration(config.Timeout) * time.Second)
		tick := time.Tick(time.Second)
		go func() {
			names = nsecRecordsWalk(config, &finishedZonewalking, &queries, &cachedZone)
			finishedZonewalking = true
		}()

		for !finishedZonewalking {
			select {
			case <-timeout:
				finishedZonewalking = true
			case <-tick:
				if config.Verbose >= 3 {
					fmt.Printf("\r[%s] NSEC zone-walking: Found %d names, %d queries, elapsed time %s", config.Zone, len(names), queries.Read(), time.Since(startScan))
				}
			}
		}
	} else {
		names = nsecRecordsWalk(config, &finishedZonewalking, &queries, &cachedZone)
	}

	if config.UpdateCache {
		for _, name := range names {
			cachedZone.Guessed[strings.TrimSuffix(tools.CleanDomainName(name), fmt.Sprintf(".%s", config.Zone))] = "1"
		}
		updateNsecCache(config.Zone, cachedZone)
	}

	log.Printf("Names #2 %d", len(names))
	return names
}

func NsecZoneCoverage(config Config) (names []string, dictionarySize int) {

	cachedZoneMap := fetchNsecCache(config.Zone)

	dictionary := make(chan string)
	go BuildLocalDictionary(config.Wordlist, dictionary)
	dictionarySize = 0
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		dictionarySize++
		if _, ok := cachedZoneMap.Guessed[guess]; ok {
			names = append(names, guess)
		}
	}

	return tools.UniqueStrings(names), dictionarySize
}
