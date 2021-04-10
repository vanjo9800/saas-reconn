package main

import (
	"flag"
	"fmt"
	"log"
	"saasreconn/pkg/tools"
	"saasreconn/pkg/zonewalk"
	"time"
)

const experimentsPerSample = 5

var nsecRecordSizes []int = []int{50, 100, 200, 500, 1000}
var nsec3RecordSizes []int = []int{1000, 2000, 5000, 10000, 20000}

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
	tools.RunShellCommand("ldns-walk", []string{fmt.Sprintf("@%s", nameserver), zone})
	results = append(results, time.Since(start).Seconds())

	return results
}

func runNsec3Experiment(zone string, nameserver string, parallelReq int, rate int) (hashes int, queries int) {
	hashes, queries = zonewalk.Nsec3ZoneMapping(zonewalk.Config{
		Mode:       2,
		Nameserver: nameserver + ":53",
		Parallel:   parallelReq,
		RateLimit:  rate,
		Timeout:    30,
		Verbose:    3,
		Zone:       zone,
	}, "03f92714", 10)

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
	fmt.Print("Mean,")
	for _, size := range sizes {
		fmt.Printf(",%.3f", sizeAccum[size]/float64(len(sizes)))
	}
	fmt.Println()
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

		printResults("saas-reconn with no rate limiting", saasReconnNoLimResults, nsecRecordSizes)
		printResults("saas-reconn with contention protection", saasReconnContLimResults, nsecRecordSizes)
		printResults("saas-reconn with safe rate limit", saasReconnSafeRateResults, nsecRecordSizes)
		printResults("ldns-walk", ldnsWalkResults, nsecRecordSizes)

	} else if *task == "nsec3-parallel" {
		//parallelOptions := []int{1, 5, 10, 20, 50, 100, 200, 500, 1000}
		parallelOptions := []int{1, 10, 20, 100}

		for _, size := range nsec3RecordSizes {
			fmt.Printf(",%d", size)
		}
		fmt.Println()

		for _, parallelReq := range parallelOptions {
			saasReconnResults := make(map[int][]float64)
			for _, size := range nsec3RecordSizes {
				for repeats := 0; repeats < experimentsPerSample; repeats++ {
					log.Printf("Size %d, experiment %d, parallel %d", size, repeats, parallelReq)
					result, _ := runNsec3Experiment(fmt.Sprintf(nsec3ZonePattern, size), *nameserver, parallelReq, 0)
					saasReconnResults[size] = append(saasReconnResults[size], float64(result))
					time.Sleep(5 * time.Second)
				}
			}

			printResults(fmt.Sprintf("saas-reconn with %d parallel queries", parallelReq), saasReconnResults, nsec3RecordSizes)
		}

	} else if *task == "nsec3-rate" {

	} else if *task == "nsec3-other" {

	} else {
		fmt.Println("Invalid task")
	}
}
