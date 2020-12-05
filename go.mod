module saasreconn

go 1.15

require github.com/OWASP/Amass/v3 v3.10.5
require saasreconn/internal/db v1.0.0
replace saasreconn/internal/db => ./internal/db
