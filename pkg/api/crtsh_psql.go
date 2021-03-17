package api

import (
	"context"
	"log"
	"saasreconn/pkg/tools"
	"time"

	"github.com/jackc/pgconn"
)

func CrtShQuery(domain string) (subdomains []string) {

	log.Println("Querying Crt.sh for " + domain)
	start := time.Now()

	time.Sleep(10 * time.Second)

	cfg, err := pgconn.ParseConfig("user=guest host=crt.sh port=5432 database=certwatch")
	if err != nil {
		log.Fatalf("[%s] Could not parse Postgres connect config: %s", domain, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pgConn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		log.Printf("[%s] pgconn failed to connect: %s", domain, err)
		for i := 1; i < 3; i++ {
			log.Println("Retrying...")
			pgConn, err = pgconn.ConnectConfig(ctx, cfg)
			if err == nil {
				break
			}
			log.Printf("[%s] pgconn failed to connect: %s", domain, err)
		}
		if err != nil {
			return subdomains
		}
	}
	defer pgConn.Close(context.Background())

	result := pgConn.ExecParams(context.Background(), "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1)) LIMIT 100000;", [][]byte{[]byte("%." + domain)}, nil, nil, nil)
	for result.NextRow() {
		cleanName := tools.CleanDomainName(string(result.Values()[0]))
		subdomains = append(subdomains, cleanName)
		if len(subdomains) > 100000 {
			log.Printf("[%s] Read more than 100000 domains, skipping for now...", domain)
			break
		}
	}
	_, err = result.Close()
	if err != nil {
		log.Printf("[%s] failed reading result: %s", domain, err)
	}
	elapsed := time.Since(start)
	log.Printf("[%s] Found %d subdomains in %s", domain, len(subdomains), elapsed)
	return subdomains
}
