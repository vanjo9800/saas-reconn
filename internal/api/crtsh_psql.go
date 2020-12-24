package api

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgconn"
)

func CrtShQuery(domain string) (subdomains []string) {

	log.Println("Querying Crt.sh for " + domain)
	start := time.Now()

	cfg, err := pgconn.ParseConfig("user=guest host=crt.sh port=5432 database=certwatch")
	if err != nil {
		log.Fatalln("Could not parse Postgres connect config:", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
	defer cancel()
	pgConn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		log.Fatalln("pgconn failed to connect:", err)
	}
	defer pgConn.Close(context.Background())

	result := pgConn.ExecParams(context.Background(), "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1)) LIMIT 100000;", [][]byte{[]byte("%." + domain)}, nil, nil, nil)
	for result.NextRow() {
		subdomains = append(subdomains, string(result.Values()[0]))
		if len(subdomains) > 100000 {
			log.Println("Read more than 100000 domains, skipping for now...")
			break;
		}
	}
	_, err = result.Close()
	if err != nil {
		log.Println("failed reading result:", err)
	}
	elapsed := time.Since(start)
	log.Printf("Found %d subdomains in %s", len(subdomains), elapsed)
	return subdomains
}
