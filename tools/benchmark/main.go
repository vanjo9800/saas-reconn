package main

import (
	"flag"
	"fmt"
	"log"
	"saasreconn/internal/tools"
	"saasreconn/internal/zonewalk"
	"time"
)

const experimentsPerSample = 1

var nsecRecordSizes []int = []int{50, 100, 200, 500, 1000}
var nsec3RecordSizes []int = []int{1000, 2000, 5000, 10000, 20000}

const nsecZonePattern string = "nsec%d.kukk.uk"
const nsec3ZonePattern string = "nsec3_%d.kukk.uk"

func runNsecExperiment(zone string, nameserver string, verbose int) (results []float64) {
	start := time.Now()
	zonewalk.NsecZoneWalking(zonewalk.Config{
		UpdateCache: false,
		Mode:        1,
		Nameservers: []string{nameserver},
		RateLimit:   -1,
		Timeout:     0, // no timeout
		Verbose:     verbose,
		Zone:        zone,
	})
	results = append(results, time.Since(start).Seconds())

	start = time.Now()
	zonewalk.NsecZoneWalking(zonewalk.Config{
		UpdateCache: false,
		Nameservers: []string{nameserver},
		RateLimit:   0,
		Timeout:     0, // no timeout
		Verbose:     verbose,
		Zone:        zone,
	})
	results = append(results, time.Since(start).Seconds())

	start = time.Now()
	zonewalk.NsecZoneWalking(zonewalk.Config{
		UpdateCache: false,
		Nameservers: []string{nameserver},
		RateLimit:   20,
		Timeout:     0, // no timeout
		Verbose:     verbose,
		Zone:        zone,
	})
	results = append(results, time.Since(start).Seconds())

	start = time.Now()
	tools.RunShellCommand("ldns-walk", []string{fmt.Sprintf("@%s", nameserver), zone})
	results = append(results, time.Since(start).Seconds())

	return results
}

func runNsec3Experiment(zone string, nameserver string, parallelReq int, rate int, verbose int) (hashes int, queries int) {
	hashes, queries = zonewalk.Nsec3ZoneEnumeration(zonewalk.Config{
		Mode:        2,
		Nameservers: []string{nameserver},
		Parallel:    parallelReq,
		RateLimit:   rate,
		Timeout:     30,
		Verbose:     verbose,
		Zone:        zone,
	}, "03f92714", 10)

	log.Printf("%s:%s - req %d - rate %d - %d hashes and %d queries", zone, nameserver, parallelReq, rate, hashes, queries)

	return hashes, queries
}

func printResults(name string, results map[int][]float64, sizes []int) {
	fmt.Print(name)
	sizeAccum := make(map[int]float64)
	for repeats := 0; repeats < experimentsPerSample; repeats++ {
		for _, size := range sizes {
			fmt.Printf(",%.3f", results[size][repeats])
			sizeAccum[size] += results[size][repeats]
		}
		fmt.Println()
	}
	// fmt.Print("Mean,")
	// for _, size := range sizes {
	// 	fmt.Printf(",%.3f", sizeAccum[size]/float64(len(sizes)))
	// }
	// fmt.Println()
}

func main() {

	// Read flags
	task := flag.String("task", "", "the task to be bechmarked")
	nameserver := flag.String("nameserver", "127.0.0.1", "nameserver to zone-walk")
	parallel := flag.Int("parallel", 10, "parallel queries")
	rate := flag.Int("rate", 0, "rate limit")
	verbose := flag.Int("verbose", 1, "verbosity level")
	size := flag.Int("size", 1000, "size")
	flag.Parse()

	if *task == "nsec" {
		saasReconnNoLimResults := make(map[int][]float64)
		saasReconnContLimResults := make(map[int][]float64)
		saasReconnSafeRateResults := make(map[int][]float64)
		ldnsWalkResults := make(map[int][]float64)

		for _, size := range nsecRecordSizes {
			for repeats := 0; repeats < experimentsPerSample; repeats++ {
				log.Printf("Size %d, experiment %d", size, repeats)
				results := runNsecExperiment(fmt.Sprintf(nsecZonePattern, size), *nameserver, *verbose)
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

		printResults("saas-reconn with no rate limiting", saasReconnNoLimResults, nsecRecordSizes)
		printResults("saas-reconn with contention protection", saasReconnContLimResults, nsecRecordSizes)
		printResults("saas-reconn with safe rate limit", saasReconnSafeRateResults, nsecRecordSizes)
		printResults("ldns-walk", ldnsWalkResults, nsecRecordSizes)

	} else if *task == "nsec3-saasreconn" {
		//parallelOptions := []int{1, 5, 10, 20, 50, 100, 200, 500, 1000}
		//parallelOptions := []int{1, 10, 20, 100}

		// for _, size := range nsec3RecordSizes {
		// 	fmt.Printf(",%d", size)
		// }
		// fmt.Println()

		// for _, parallelReq := range parallelOptions {
		// saasReconnResults := make(map[int][]float64)
		// for _, size := range nsec3RecordSizes {
		// 	for repeats := 0; repeats < experimentsPerSample; repeats++ {
		log.Printf("Size %d, parallel %d, rate %d", *size, *parallel, *rate)
		result, _ := runNsec3Experiment(fmt.Sprintf(nsec3ZonePattern, *size), *nameserver, *parallel, *rate, *verbose)
		fmt.Printf(",%d", result)
		// time.Sleep(20 * time.Second)
		// 	}
		// }

		// printResults(fmt.Sprintf("saas-reconn with %d p. queries and %d rate limit", *parallel, *rate), saasReconnResults, nsec3RecordSizes)
		// }
	} else if *task == "nsec3-other" {

	} else {
		fmt.Println("Invalid task")
	}
}