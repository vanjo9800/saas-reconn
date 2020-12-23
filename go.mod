module saasreconn

go 1.15

require saasreconn/internal/db v1.0.0

replace saasreconn/internal/db => ./internal/db

require (
	github.com/chromedp/chromedp v0.5.4 // indirect
	github.com/jackc/pgconn v1.8.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	saasreconn/internal/api v0.0.0-00010101000000-000000000000
	saasreconn/internal/provider v1.0.0
)

replace saasreconn/internal/provider => ./internal/provider

replace saasreconn/internal/api => ./internal/api
