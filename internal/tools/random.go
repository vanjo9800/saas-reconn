package tools

import (
	"math/rand"
	"strings"
	"sync"
	"time"
)

// Only one thread can use the random subdomain generator at once as the random implementation is not concurrent
var randomLock sync.Mutex
var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomStringWithCharset(maxLength int, charset string) string {
	var result strings.Builder

	randomLock.Lock()
	length := seededRand.Intn(maxLength)
	for i := 0; i < length; i++ {
		index := seededRand.Intn(len(charset))
		result.WriteByte(charset[index])
	}
	randomLock.Unlock()

	return result.String()
}
