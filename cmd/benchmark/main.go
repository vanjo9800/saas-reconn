package main

import (
	"flag"
	"fmt"
	"log"
	"saasreconn/pkg/tools"
	"saasreconn/pkg/zonewalk"
	"time"
)

const experimentsPerSample = 3

var nsecRecordSizes []int = []int{50} //, 100, 200, 500, 1000}

const nsecZonePattern string = "nsec%d.kukk.uk"
const nsec3ZonePattern string = "nsec3_%d.kukk.uk"

func runNsecExperiment(zone string, nameserver string) (results []float64) {
	start := time.Now()
	zonewalk.NsecZoneWalking(zonewalk.Config{
		UpdateCache: false,
		Mode:        1,
		Nameserver:  nameserver + ":53",
		RateLimit:   -1,
		Timeout:     0, // no timeout
		Verbose:     1,
		Zone:        zone,
	})
	results = append(results, time.Since(start).Seconds())

	start = time.Now()
	zonewalk.NsecZoneWalking(zonewalk.Config{
		UpdateCache: false,
		Nameserver:  nameserver + ":53",
		RateLimit:   0,
		Timeout:     0, // no timeout
		Verbose:     1,
		Zone:        zone,
	})
	results = append(results, time.Since(start).Seconds())

	start = time.Now()
	zonewalk.NsecZoneWalking(zonewalk.Config{
		UpdateCache: false,
		Nameserver:  nameserver + ":53",
		RateLimit:   20,
		Timeout:     0, // no timeout
		Verbose:     1,
		Zone:        zone,
	})
	results = append(results, time.Since(start).Seconds())

	start = time.Now()
	tools.RunShellCommand("ldns-walk", []string{"-f", fmt.Sprintf("@%s", nameserver), zone})
	results = append(results, time.Since(start).Seconds())

	return results
}

func printResults(name string, results map[int][]float64) {
	fmt.Print(name)
	for repeats := 0; repeats < experimentsPerSample; repeats++ {
		for _, size := range nsecRecordSizes {
			fmt.Printf(",%.3f", results[size][repeats])
		}
		fmt.Println()
	}
}

func main() {

	// Read flags
	task := flag.String("task", "", "the task to be bechmarked")
	nameserver := flag.String("nameserver", "127.0.0.1", "nameserver to zone-walk")
	flag.Parse()

	if *task == "nsec" {
		saasReconnNoLimResults := make(map[int][]float64)
		saasReconnContLimResults := make(map[int][]float64)
		saasReconnSafeRateResults := make(map[int][]float64)
		ldnsWalkResults := make(map[int][]float64)

		for _, size := range nsecRecordSizes {
			for repeats := 0; repeats < experimentsPerSample; repeats++ {
				log.Printf("Size %d, experiment %d", size, repeats)
				results := runNsecExperiment(fmt.Sprintf(nsecZonePattern, size), *nameserver)
				saasReconnNoLimResults[size] = append(saasReconnNoLimResults[size], results[0])
				saasReconnContLimResults[size] = append(saasReconnContLimResults[size], results[1])
				saasReconnSafeRateResults[size] = append(saasReconnSafeRateResults[size], results[2])
				ldnsWalkResults[size] = append(ldnsWalkResults[size], results[3])
			}
		}

		for _, size := range nsecRecordSizes {
			fmt.Printf(",%d", size)
		}
		fmt.Println()

		printResults("saas-reconn with no rate limiting", saasReconnNoLimResults)
		printResults("saas-reconn with contention protection", saasReconnContLimResults)
		printResults("saas-reconn with safe rate limit", saasReconnSafeRateResults)
		printResults("ldns-walk", ldnsWalkResults)

	} else if *task == "nsec3" {

	} else {
		fmt.Println("Invalid task")
	}
}
