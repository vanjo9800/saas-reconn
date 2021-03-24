package api

import (
	"context"
	"log"
	"saasreconn/pkg/tools"
	"time"

	"github.com/jackc/pgconn"
)

const connectionRetries int = 3

func CrtShQuery(domain string, verbosity int) (subdomains []string) {

	if verbosity >= 2 {
		log.Printf("[Crt.sh] Querying Crt.sh for %s", domain)
	}
	start := time.Now()

	// TODO - revise
	time.Sleep(10 * time.Second)

	cfg, err := pgconn.ParseConfig("user=guest host=crt.sh port=5432 database=certwatch")
	if err != nil {
		log.Printf("[Crt.sh] Could not parse Postgres connect config: %s", err)
		return subdomains
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pgConn, err := pgconn.ConnectConfig(ctx, cfg)
	failedConnects := 0
	for err != nil {
		if verbosity >= 4 {
			log.Printf("[Crt.sh] pgconn failed to connect: %s", err)
		}
		failedConnects++
		if failedConnects == connectionRetries {
			return subdomains
		}
		pgConn, err = pgconn.ConnectConfig(ctx, cfg)
	}
	defer pgConn.Close(context.Background())

	result := pgConn.ExecParams(context.Background(), "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1)) LIMIT 100000;", [][]byte{[]byte("%." + domain)}, nil, nil, nil)
	for result.NextRow() {
		cleanName := tools.CleanDomainName(string(result.Values()[0]))
		subdomains = append(subdomains, cleanName)
		subdomains = tools.UniqueStrings(subdomains)
		if len(subdomains) > 100000 {
			if verbosity >= 3 {
				log.Printf("[Crt.sh] Read more than 100000 domains for %s, skipping for now...", domain)
			}
			break
		}
	}
	_, err = result.Close()
	if err != nil {
		log.Printf("[Crt.sh] failed reading query result: %s", err)
	}
	elapsed := time.Since(start)
	if verbosity >= 2 {
		log.Printf("[Crt.sh] Found %d subdomains for %s in %s", len(subdomains), domain, elapsed)
	}
	return subdomains
}
