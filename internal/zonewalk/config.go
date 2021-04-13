package zonewalk

// Config is a class for configuration of the zone-walking module
type Config struct {
	MappingCache    bool
	GuessesCache    bool
	UpdateCache     bool
	Hashcat         bool
	Mode            int
	Nameservers     []string
	NameserverIndex int
	Parallel        int
	RateLimit       int
	Timeout         int
	Verbose         int
	Wordlist        string
	Zone            string
}
