package samlmux

import (
	"crypto/tls"
	"net/http"
)

func httpCookieNRelayState(cert *tls.Certificate, req *http.Request) (*http.Cookie, string, error) {

	// Return the token.
	return &http.Cookie{
		Name:     "samlmux",
		Value:    payloadStr,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   30,
	}
}
