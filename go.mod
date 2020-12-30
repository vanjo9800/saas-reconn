module saasreconn

go 1.15

require (
	gopkg.in/yaml.v2 v2.4.0 // indirect
	saasreconn/internal/api v0.0.0-00010101000000-000000000000
	saasreconn/internal/checks v1.0.0
	saasreconn/internal/db v1.0.0
	saasreconn/internal/provider v1.0.0
)

replace saasreconn/internal/provider => ./internal/provider

replace saasreconn/internal/db => ./internal/db

replace saasreconn/internal/api => ./internal/api

replace saasreconn/internal/checks => ./internal/checks
