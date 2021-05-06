# saas-reconn
A reconnaissance tool for discovery of SaaS endpoints used by corporate organisations

## Main Usage
The `saas-reconn` tool supports the following main commands:
- `passive-enum` performing *passive subdomain enumeration* of a list of SaaS providers. It accepts the following parameters:
```
Usage of passive-enum:
  -dataproviders string
        a comma separated list of passive data providers to use (supported providers: Crt.sh, VirusTotal, SearchDNS) (default "Crt.sh")
  -endpoints-config string
        a SaaS providers endpoints file (default "configs/saas-endpoints.yaml")
  -provider string
        query for a specific provider
  -verbose int
        verbosity factor (default 2)
  -vtotal-key string
        VirusTotal API key
```
- `zonewalk` performing *DNSSEC zone-walking* of a list of SaaS providers' zones, or a specific zone and nameserver configuration. It uses the following parameters:
```
Usage of zonewalk:
  -domain string
        run zone-walking for a specific domain
  -endpoints-config string
        a SaaS providers endpoints file (default "configs/saas-endpoints.yaml")
  -hashcat
        use hashcat for brute forcing NSEC3 hashes (default true)
  -list-providers
        list all supported providers
  -mode int
         what mode to use for zone-walking (0 for just DNSSEC check, 1 for both enumeration and brute forcing, 2 for just enumeration and storing cache, and 3 for just brute forcing using cache) (default 1)
  -nameserver string
        run zone-walking for a specific nameserver
  -no-cache
        a bool whether to use pre-existing
  -parallel int
        number of DNS requests to send in parallel (default 5)
  -provider string
        run zone-walking for a specific provider
  -rate-limit int
        limit the number of DNS requests per second to avoid blocking (0 for minimal limit for contention protection, -1 for no limit at all) (default 20)
  -timeout int
        number of seconds to run a zone enumeration per zone (default 60)
  -update-cache
        should the command update the current zone-walking cache entries (default true)
  -verbose int
        verbosity factor (default 3)
```
- `active-lookup` performing *web page enumeration and content validation* of the previously obtained results for a corporate organisation. It accepts as input a list of corporate names, as well as the following parameters:
```
Usage of active-lookup:
  -cache-lifetime float
        the lifetime of our HTTP requests cache (measured in hours) (default 48)
  -endpoints-config string
        a SaaS providers endpoints file (default "configs/saas-endpoints.yaml")
  -no-cache
        a bool whether to use pre-existing
  -parallel-requests int
        how many HTTP requests should we issue in parallel (default 5)
  -provider string
        do an active check for a specific SaaS provider
  -verbose int
        verbosity factor (default 2)
```
- `report` generating user-friendly reports of the enumerated results for a corporate organisation. It accepts as input a list of corporate names, as well as the following parameters:
```
Usage of report:
  -confidence-threshold int
        confidence treshold (default 2)
  -endpoints-config string
        a SaaS providers endpoints file (default "configs/saas-endpoints.yaml")
  -extended
        search for any subdomains matching corporate name
  -logfile string
        log just endpoint names
  -no-searchdns
        do not suggest other potential subdomains from SearchDNS
  -outfile string
        set a custom name for the report file
  -screenshot
        take page screenshots (default true)
  -verbose int
        verbosity factor (default 2)
```

## Useful Tools
For more refined use, `saas-reconn` also offers the following functional commands:
- `export-dictionary` which exports the current dictionary used in hash brute forcing to the *standard output*
- `fetch-provider-names` which prints all the enumerated endpoints of a SaaS provider on the *standard output*
- `johntheripper-format` which converts a `saas-reconn` zone-walking cache entry with enumeration data into a suitable input file to be passed to **John the Ripper** for a brute force attack
- `nsec3map-format` which converts a `saas-reconn` zone-walking cache entry with enumeration data into a suitable input file to be passed to `nsec3map` for a brute force attack
- `nsec3walker-format` which converts a `saas-reconn` zone-walking cache entry with enumeration data into a suitable input file to be passed to `nsec3walker` for a brute force attack
- `wordlist-evaluate` which evaluates the coverage of the currently used wordlists under `resources/wordlists` against all the accumulated zone-walking enumeration data
