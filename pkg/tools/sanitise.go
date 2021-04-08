package tools

import (
	"regexp"
	"strings"
)

var domainsCleanClues map[string][]string = map[string][]string{
	"bluejeans.com":      {`"applicationTime":\d+`, `"theme_token":"[0-9a-zA-Z]+"`, `jQuery.extend\(.*?"filters":\[\]}}}}}}\);`},
	"box.com":            {`requestToken\s=\s'[a-zA-Z0-9]+'`, `value="[0-9a-zA-Z]+"`},
	"mailchimpsites.com": {`<script>.*?akamaihd.net.*?</script>`},
	"maptq.com":          {`value="[a-zA-Z0-9/=+]+"`, `action="[^"]+"`, `<span id="ui_PageBottom_lbl_Instance_Id">\d+</span>`},
	"okta.com":           {`baseUrl\s=\s'.*?'`, `<script>var w=window;if.*?clientip:.*?</script>`},
	"onelogin.com":       {`NREUM.info={.*?}|value="[a-zA-Z0-9/=+]+"`},
	"sharefile.com":      {`[nN]once(":|=)"[a-zA-Z0-9/=+]+"`, `oAuthViewModel = {.*?"DisableRs3":(true|false)};`, `v=[0-9a-zA-Z_-]+`},
	"slack.com":          {`<!--\sslack-www.*? -->`},
	// "outlook":       {`[a-z]+cdn[.]ms(ft)?auth[.]net`, `"hash":"[a-zA-Z0-9]+"`, `Config=\{.*?\};`},
}

var domainsInvalidClues map[string][]string = map[string][]string{
	"atlassian.net": {`Atlassian Cloud Notifications - Page Unavailable`},
	"bluejeans.com": {`Try for Free`},
	// Non-existing Box.com pages use the default SVG box logo
	"box.com":            {`<svg class="logo" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="49px" height="27px" viewBox="0 0 49 27" version="1.1" role="img">`},
	"github.com":         {`not-found-search`},
	"mailchimp.com":      {`Launch your website for free`},
	"mailchimpsites.com": {`We can't find that page`, ` Launch your website for free`},
	// Okta.com pages that correspond to organisations may have the organisation logo, or use the Okta logo, but as an alternative name have the organization name
	// e.g. logoText: 'verizonmedia logo'
	"okta.com":      {`logoText: ' logo',`},
	"remarkety.com": {`remarkety_logo_red.png`},
	"sharefile.com": {`Enter your account's subdomain to continue`},
	"slack.com":     {`There has been a glitch...`},
	// Qualtrics.com pages look visually alike for existing and non-existing organizations, but the existing ones have an Organization ID: field in their HTML containing the organization name
	"qualtrics.com": {`<div class="psw_cons_msg ng-hide" ng-show="lc.showOrganizationHeader"><div class="ng-binding">Organization ID: <b class="ng-binding"></b></div></div>`},
	"zendesk.com":   {`Oops! This help centre no longer exists`},
}

func CleanResponse(responseBody string, hostname string, base string) string {
	cleanBody := responseBody

	// Remove the hostname
	reg := regexp.MustCompile(`\Q` + hostname + `\E`)
	cleanBody = reg.ReplaceAllString(cleanBody, "")

	for provider, removeStrings := range domainsCleanClues {
		if strings.Contains(base, provider) {
			for _, toClean := range removeStrings {
				reg = regexp.MustCompile(toClean)
				cleanBody = reg.ReplaceAllString(cleanBody, "")
			}
		}
	}

	return cleanBody
}

func IsInvalidTextResponse(responseBody string, base string) bool {

	for provider, failedClues := range domainsInvalidClues {
		if strings.Contains(base, provider) {
			for _, failedText := range failedClues {
				if strings.Contains(responseBody, failedText) {
					return true
				}
			}
		}
	}

	return false
}
