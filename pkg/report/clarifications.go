package report

var providerClarifications map[string]string = map[string]string{
	// "Atlassian": "",
	"Citrix ShareFile": `Existing ShareFile company subdomains present the user with a login prompt. <br/> Non-existing ShareFile company subdomains redirect the user to <a target="_blank" href="https://secure.sharefile.com/Authentication/Login">https://secure.sharefile.com/Authentication/Login</a> and prompt the user for an organisation name.`,
	"Okta":             `Existing Okta company subdomains show the company logo, or include the company name in the <code>alt=</code> parameter of the logo.<br/> Non-existing Okta company subdomains use the default Okta logo and do not include a company name in the <code>alt=</code> parameter.`,
	"OneLogin":         `Existing OneLogin company subdomains present the user with a login prompt.<br/> Non-existing OneLogin company subdomains redirect the user to <a targer="_blank" href="https://app.onelogin.com/login">https://app.onelogin.com/login</a> and prompt the user for an organisation name.`,
	"Qualtrics":        `Existing Qualtrics company subdomains have an organization ID embedded in their body, but hidden for the user <code> Organization ID: &lt;b class="ng-binding"&gt;aol&lt;/b&gt;</code>.<br/> For non-existing Qualtrics company subdomains the inner container is empty.`,
	"Zoom":             `Existing Zoom company subdmains resolve to a Zoom-branded sign-in page. <br/> Non-existing Zoom company subdomains do not resolve at all <a href="http://saas-reconn.zoom.us" target="_blank">http://saas-reconn.zoom.us</a>.`,
}
