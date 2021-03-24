package report

import (
	"fmt"
	"io/ioutil"
	"log"
	"saasreconn/pkg/db"
	"saasreconn/pkg/tools"
	"sort"
	"strings"
)

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
				<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta2/dist/js/bootstrap.bundle.min.js" integrity="sha384-b5kHyXgcpbZJO/tY9Ul7kGkf1S0CWuKcCD38l8YkeH8z8QjE0GmW1gYU5S9FOnJ0" crossorigin="anonymous"></script>
				%s
				<hr/>
				<h2>Explanation of results</h2>
				<p id="confidence">
					<h3>Confidence</h3>
					Our application adds a <i>confidence</i> score to each of the reported subdomains based on what level of processing and filtering it has undergone. For now, we have the following levels:
					<ul>
						<li><code>60&#37;</code> marking the subdomain has come from an online database such as (Crt.sh, SearchDNS, VirusTotal) and no further checks have been performed. It may have existed at some point, but be inexistent now.</li>
						<li><code>70&#37;</code> marking the subdomain has come from DNS zone-walkng. It is part of the zone as of the current moment, but its content has not been analysed.</li>
						<li><code>80&#37;</code> marking the subdomain has undergone an active check. It resolves to an IP address and it can be accessed with a successful HTTP request producing non-error page content.</li>
						<li><code>90&#37;</code> marking the subdomain has undergone an active check and its content body has the corporate's logo.</li>
					</ul>
				</p>
				<p id="discovered-by">
					<h3>Discovery sources</h3>
					Our information discovery comes from the following sources:
					<ul>
						<li><strong><a target="_blank" href="https://crt.sh/">Crt.sh</a></strong>: An online free database with SSL/TLS certificate historical information. It is used to extract common names used in certificate that match our corporate, or SaaS providers.</li>
						<li><strong><a target="_blank" href="https://searchdns.netcraft.com/">Netcraft SearchDNS</a></strong>: An online tool for searching names in DNS zones fetched by users of the Netcraft Toolbar.</li>
						<li><strong><a target="_blank" href="https://www.virustotal.com/gui/home/search">VirusTotal</a></strong>: An online database with historical security information for various files, URLs, and domains.</li>
						<li><strong>Zone-walking</strong>: We have come across the subdomain when performaing DNS zone-walking of the zone (supporting both NSEC and NSEC3 signatures).</li>
						<li><strong>Active validation</strong>: We have performed an <i>active check</i> on the subdomain and it resolves to an IP address and can be accessed by a successful HTTP request returning non-error page content.</li>
					</ul>
				</p>
				<hr/>
				%s
			</div>
	   </body>
	</html>`,
		corporate,
		generateCSSStyle(),
		generateTables(subdomains),
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
	}`
}

func Map(elements []string, f func(string) string) []string {
	mappedElements := make([]string, len(elements))
	for i, el := range elements {
		mappedElements[i] = f(el)
	}
	return mappedElements
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
		headers := []string{"Subdomain", "<a href=\"#confidence\">Confidence</a>", "<a href=\"#discovered-by\">Discovered by</a>", "Screenshot"}
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
		tableRepresenation += "<p>" + tableStructure + "</p>"
	}

	return tableRepresenation
}

func generateFooter() string {
	return "<footer><p>Generated by <code>saas-reconn</code>, developed by Ivan Ivanov</p></footer>"
}
