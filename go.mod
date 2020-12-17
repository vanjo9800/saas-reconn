module saasreconn

go 1.15

require github.com/OWASP/Amass/v3 v3.10.5
require saasreconn/internal/db v1.0.0
replace saasreconn/internal/db => ./internal/db
require saasreconn/internal/provider v1.0.0
replace saasreconn/internal/provider => ./internal/provider
require saasreconn/internal/dns v1.0.0
replace saasreconn/internal/dns => ./internal/dns
require saasreconn/internal/api v1.0.0
replace saasreconn/internal/api => ./internal/api
