module saasreconn

go 1.15

require (
	github.com/miekg/dns v1.1.35 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	saasreconn/pkg/api v0.0.0-00010101000000-000000000000
	saasreconn/pkg/checks v1.0.0
	saasreconn/pkg/db v1.0.0
	saasreconn/pkg/dns v1.0.0
	saasreconn/pkg/provider v1.0.0
)

replace saasreconn/pkg/provider => ./pkg/provider

replace saasreconn/pkg/db => ./pkg/db

replace saasreconn/pkg/dns => ./pkg/dns

replace saasreconn/pkg/api => ./pkg/api

replace saasreconn/pkg/checks => ./pkg/checks

replace saasreconn/pkg/cache => ./pkg/cache
