// VibeGuard sample: Go math/rand used for security-relevant values.
package main

import (
	"fmt"
	"math/rand"
)

// VG-CRYPTO-002 — math/rand used to mint a session id.
func newSessionId() int {
	sessionId := rand.Intn(1000000)
	return sessionId
}

// VG-CRYPTO-002 — math/rand for a CSRF token.
func newCsrfToken() float64 {
	csrfToken := rand.Float64()
	return csrfToken
}

func main() {
	fmt.Println(newSessionId(), newCsrfToken())
}
