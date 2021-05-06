package report

import (
	"fmt"
	"io/ioutil"
	"log"
	"saasreconn/internal/db"
	"saasreconn/internal/tools"
	"sort"
	"strings"
)

var confidenceReporting map[int]string = map[int]string{
	-1: "marking the subdomain has undergone an active check. It <strong>does not</strong> resolve to an IP address, <strong>cannot</strong> be accessed via HTTP, or results in an error page content.",
	0:  "marking the subdomain has not been explored by the tool at all and there is no information about it.",
	1:  "marking the subdomain has come from an online database such as (Crt.sh, SearchDNS, VirusTotal) and no further checks have been performed. It is not confirmed it is still resolvable and accessible.",
	2:  "marking the subdomain has come from an online database such as (Crt.sh, SearchDNS, VirusTotal) and contains the name of the corporate, but no further checks have been performed. It is not confirmed it is still resolvable and accessible.",
	3:  "marking the subdomain has come from DNS zone-walkng. It is part of the zone as of the current moment, but it is confirmed whether it is accessible.",
	4:  "marking the subdomain has undergone an active check. It resolves to an IP address, can be accessed via HTTTP and produces a non-error page content.",
	5:  "marking the subdomain has undergone an active check and it is associated with the corporate based on its content.",
}

var sourcesLinks map[string]string = map[string]string{
	"Crt.sh":             "https://crt.sh/",
	"Netcraft SearchDNS": "https://searchdns.netcraft.com/",
	"VirusTotal":         "https://www.virustotal.com/gui/home/search",
}

var sourcesDescription map[string]string = map[string]string{
	"Crt.sh":             "An online free database with SSL/TLS certificate historical information. It is used to extract common names used in certificate that match our corporate, or SaaS providers.",
	"Netcraft SearchDNS": "An online tool for searching names in DNS zones fetched by users of the Netcraft Toolbar.",
	"VirusTotal":         "An online database with historical security information for various files, URLs, and subdomains.",
	"Zone-walking":       "We have come across the subdomain when performaing DNS zone-walking of the zone (supporting both NSEC and NSEC3 signatures).",
	"Active validation":  "We have performed an <i>active check</i> on the subdomain and it resolves to an IP address and can be accessed by a successful HTTP request returning non-error page content.",
}

func ExportToHTML(subdomains []db.ProviderData, corporate string, filename string) {
	htmlContent := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BmbxuPwQa2lc/FVzBcNJ7UAyJxM6wuqIj61tLrc4wSX0szH/Ev+nYRRuWlolflfl" crossorigin="anonymous">
			<title>Exposed pages for '%s'</title>
			<style>%s</style>
		</head>
		<body>
			<div class="container">
				<h1>Exposed pages from <i>Software-as-a-Service (SaaS)</i> providers</h1>
				<hr/>
				<p>
				<h4 class="potential-header">Found %d potential names</h4>
				</p>
				<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta2/dist/js/bootstrap.bundle.min.js" integrity="sha384-b5kHyXgcpbZJO/tY9Ul7kGkf1S0CWuKcCD38l8YkeH8z8QjE0GmW1gYU5S9FOnJ0" crossorigin="anonymous"></script>
				%s
				<hr/>
				<h2>Explanation of results</h2>
				<p id="confidence">
					<h3>Confidence scores</h3>
					Our application adds a <i>confidence</i> score to each of the reported subdomains based on what level of processing and filtering it has undergone. For now, we have the following levels:
					%s
				</p>
				<p id="discovered-by">
					<h3>Discovery sources</h3>
					Our information discovery comes from the following sources:
					%s
				</p>
				<hr/>
				%s
			</div>
	   </body>
	</html>`,
		corporate,
		generateCSSStyle(),
		countSubdomains(subdomains),
		generateTables(subdomains),
		generateConfidenceReport(),
		generateSourcesReport(),
		generateFooter())

	// Save HTML report
	err := ioutil.WriteFile(fmt.Sprintf("reports/%s.html", tools.NameToPath(filename)), []byte(htmlContent), 0755)
	if err != nil {
		log.Printf("Could not save HTML report %s: %s", filename, err)
		return
	}
}

func generateCSSStyle() string {
	return `
	footer p {
		text-align: right;
		font-style: italic;
	}
	h1 {
		text-align: left;
		font-weight: bold;
	}
	h3 {
		margin: 0;
		padding: 5px;
	}
	.potential-header {
		color: gray;
		font-style: italic;
	}
	th {fdfdfgdfgdf
		font-weight: bold;
	}
	.table-header {
		width: 100%;
		text-align: center;
		font-weight: bold;
		color: white;
		background-color: black;
	}
	table {
		border-collapse: collapse;
		width: 100%;
	}
	th, td {
		border: 1px solid #ccc;
		padding: 10px;
		text-align: center
	}
	table.alternating tr:nth-child(even) {
		background-color: #eee;
	}
	table.alternating tr:nth-child(odd) {
		background-color: #fff;
	}
	col.subdomain {
		width: 30%;
	}
	col.confidence {
		width: 20%;
	}
	col.discovered-by {
		width: 20%;
	}
	col.screenshot {
		width: 30%;
	}
	img.screenshot {
		max-width: 100%;
	}
	.card {
		display: block
	}`
}

func Map(elements []string, f func(string) string) []string {
	mappedElements := make([]string, len(elements))
	for i, el := range elements {
		mappedElements[i] = f(el)
	}
	return mappedElements
}

func countSubdomains(subdomains []db.ProviderData) (count int) {
	count = 0
	for _, providerData := range subdomains {
		for _, names := range providerData.Subdomains {
			count += len(names)
		}
	}
	return count
}

func generateTables(subdomains []db.ProviderData) (tableRepresenation string) {

	// Sort SaaS providers alphabetically
	sort.SliceStable(subdomains, func(i, j int) bool {
		return subdomains[i].Provider < subdomains[j].Provider
	})
	for _, providerData := range subdomains {
		var tableStructure string

		// Provider title
		tableStructure += fmt.Sprintf(`<div class="table-header"><h3>%s</h3></div>`, providerData.Provider)

		tableHTML := `
			<col class="subdomain">
			<col class="confidence">
			<col class="discovered-by">
			<col class="screenshot">`
		headers := []string{"Subdomain", "<a href=\"#confidence\">Confidence score</a>", "<a href=\"#discovered-by\">Discovered by</a>", "Screenshot"}
		tableHeaders := "<thead><tr>" + strings.Join(Map(headers, func(header string) string {
			return "<th>" + header + "</th>"
		}), "") + "</tr></thead>"
		tableHTML += tableHeaders + "<tbody>"

		overallNames := []db.Subdomain{}
		for _, names := range providerData.Subdomains {
			overallNames = append(overallNames, names...)
		}
		if len(overallNames) == 0 {
			continue
		}

		sort.SliceStable(overallNames, func(i, j int) bool {
			return overallNames[i].Confidence > overallNames[j].Confidence
		})
		for _, subdomain := range overallNames {
			var tableRow string

			// Handle subdomain and link
			tableRow += fmt.Sprintf(`<td><a target="_blank" href="%s">%s</a></td>`, tools.URLFromSubdomainEntry(subdomain.Name), subdomain.Name)

			// Handle confidence
			tableRow += fmt.Sprintf(`<td>%d</td>`, subdomain.Confidence)

			// Handle found by
			tableRow += fmt.Sprintf(`<td>%s</td>`, strings.Join(subdomain.DiscoveredBy, ", "))

			// Handle screenshot
			if subdomain.Screenshot == "N/A" {
				tableRow += "<td>N/A</td>"
			} else {
				tableRow += fmt.Sprintf(`<td><img class="screenshot" src="%s" alt="N/A"></td>`, subdomain.Screenshot)
			}

			tableHTML += "<tr>" + tableRow + "</tr>"
		}
		tableHTML += "</tbody>"

		tableStructure += "<table class=\"table table-striped\">" + tableHTML + "</table>"

		clarificationInfo := ""
		if info, exists := providerClarifications[providerData.Provider]; exists {
			clarificationInfo = fmt.Sprintf(`<p>
				<a class="btn btn-link" data-bs-toggle="collapse" href="#clarification-%s" role="button" aria-expanded="false" aria-controls="clarification-%s">
					Clarification of result
				</a>
				</p>`, tools.NameToPath(providerData.Provider), tools.NameToPath(providerData.Provider))
			clarificationInfo += fmt.Sprintf(`<div class="collapse" id="clarification-%s">
				<div class="card card-body">
					%s
				</div>
				</div>`, tools.NameToPath(providerData.Provider), info)
		}
		tableRepresenation += "<p>" + tableStructure + clarificationInfo + "</p><hr/>"
	}

	return tableRepresenation
}

func generateConfidenceReport() string {
	listItems := []string{}
	values := make([]int, 0, len(confidenceReporting))
	for value := range confidenceReporting {
		values = append(values, value)
	}
	sort.Ints(values)
	for _, value := range values {
		listItems = append(listItems, fmt.Sprintf("<li><code>%d</code>: %s</li>", value, confidenceReporting[value]))
	}
	return "<ul>" + strings.Join(listItems, "\n") + "</ul>"
}

func generateSourcesReport() string {
	listItems := []string{}
	sources := make([]string, 0, len(sourcesDescription))
	for source := range sourcesDescription {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		sourceStyle := source
		if link, exists := sourcesLinks[source]; exists {
			sourceStyle = fmt.Sprintf("<a href=\"%s\" target=\"_blank\">%s</a>", link, source)
		}
		listItems = append(listItems, fmt.Sprintf("<li><strong>%s</strong>: %s</li>", sourceStyle, sourcesDescription[source]))
	}
	return "<ul>" + strings.Join(listItems, "\n") + "</ul>"
}

func generateFooter() string {
	return "<footer><p>Generated by <code>saas-reconn</code></p></footer>"
}
