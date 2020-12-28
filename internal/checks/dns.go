package checks

import (
	"net"
)

func (checkRange SubdomainRange) Resolvable() (resolvableRange SubdomainRange) {
	resolvableRange.Base = checkRange.Base
	for _, prefix := range checkRange.Prefixes {
		address, err := net.LookupHost(prefix + "." + resolvableRange.Base)
		if err == nil && len(address) > 0 {
			resolvableRange.Prefixes = append(resolvableRange.Prefixes, prefix)
		}
	}

	return resolvableRange
}
