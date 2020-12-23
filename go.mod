module saasreconn

go 1.15

require saasreconn/internal/db v1.0.0

replace saasreconn/internal/db => ./internal/db

require saasreconn/internal/provider v1.0.0

replace saasreconn/internal/provider => ./internal/provider

replace saasreconn/internal/api => ./internal/api
