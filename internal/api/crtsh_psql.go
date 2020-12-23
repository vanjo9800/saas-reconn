package api

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgconn"
)

func CrtShQuery(domain string) (subdomains []string) {

	log.Println("Querying Crt.sh for " + domain)

	cfg, err := pgconn.ParseConfig("user=guest host=crt.sh port=5432 database=certwatch")
	if err != nil {
		log.Fatalln("Could not parse Postgres connect config:", err)
	}

	pgConn, err := pgconn.ConnectConfig(context.Background(), cfg)
	if err != nil {
		log.Fatalln("pgconn failed to connect:", err)
	}
	defer pgConn.Close(context.Background())

	result := pgConn.ExecParams(context.Background(), "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1));", [][]byte{[]byte("%." + domain)}, nil, nil, nil)
	for result.NextRow() {
		subdomains = append(subdomains, string(result.Values()[0]))
	}
	_, err = result.Close()
	if err != nil {
		log.Fatalln("failed reading result:", err)
	}

	log.Println("Found " + fmt.Sprint(len(subdomains)) + " subdomains")
	return subdomains
}
