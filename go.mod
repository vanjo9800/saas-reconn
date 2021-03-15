module saasreconn

go 1.16

require (
	cloud.google.com/go v0.78.0 // indirect
	github.com/chromedp/chromedp v0.6.8 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/jackc/pgconn v1.8.0 // indirect
	github.com/miekg/dns v1.1.35 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	golang.org/x/oauth2 v0.0.0-20210220000619-9bb904979d93 // indirect
	golang.org/x/sys v0.0.0-20210305230114-8fe3ee5dd75b // indirect
	google.golang.org/genproto v0.0.0-20210303154014-9728d6b83eeb // indirect
	google.golang.org/grpc v1.36.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	saasreconn/pkg/api v0.0.0-00010101000000-000000000000
	saasreconn/pkg/cache v1.0.0
	saasreconn/pkg/checks v1.0.0
	saasreconn/pkg/db v1.0.0
	saasreconn/pkg/dns v1.0.0
	saasreconn/pkg/provider v1.0.0
	saasreconn/pkg/tools v1.0.0
	saasreconn/pkg/zonewalk v1.0.0
)

replace saasreconn/pkg/provider => ./pkg/provider

replace saasreconn/pkg/db => ./pkg/db

replace saasreconn/pkg/dns => ./pkg/dns

replace saasreconn/pkg/zonewalk => ./pkg/zonewalk

replace saasreconn/pkg/api => ./pkg/api

replace saasreconn/pkg/checks => ./pkg/checks

replace saasreconn/pkg/cache => ./pkg/cache

replace saasreconn/pkg/tools => ./pkg/tools
