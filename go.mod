module saasreconn

go 1.16

require (
	cloud.google.com/go v0.78.0 // indirect
	github.com/chromedp/chromedp v0.6.8 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/jackc/pgconn v1.8.0 // indirect
	github.com/johnfercher/maroto v0.31.0 // indirect
	github.com/miekg/dns v1.1.35 // indirect
	github.com/unidoc/unipdf/v3 v3.20.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	golang.org/x/oauth2 v0.0.0-20210220000619-9bb904979d93 // indirect
	golang.org/x/sys v0.0.0-20210305230114-8fe3ee5dd75b // indirect
	google.golang.org/genproto v0.0.0-20210303154014-9728d6b83eeb // indirect
	google.golang.org/grpc v1.36.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	saasreconn/internal/api v0.0.0-00010101000000-000000000000
	saasreconn/internal/cache v1.0.0
	saasreconn/internal/checks v1.0.0
	saasreconn/internal/db v1.0.0
	saasreconn/internal/provider v1.0.0
	saasreconn/internal/report v0.0.0-00010101000000-000000000000 // indirect
	saasreconn/internal/tools v1.0.0
	saasreconn/internal/zonewalk v1.0.0
)

replace saasreconn/internal/provider => ./internal/provider

replace saasreconn/internal/db => ./internal/db

replace saasreconn/internal/zonewalk => ./internal/zonewalk

replace saasreconn/internal/api => ./internal/api

replace saasreconn/internal/checks => ./internal/checks

replace saasreconn/internal/cache => ./internal/cache

replace saasreconn/internal/tools => ./internal/tools

replace saasreconn/internal/report => ./internal/report
