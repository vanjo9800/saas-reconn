module checks

go 1.16

require (
	github.com/chromedp/chromedp v0.6.5
	saasreconn/pkg/cache v1.0.0-00010101000000-000000000000
)

replace saasreconn/pkg/cache => ../cache
