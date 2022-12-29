package security

import "net/http"

// ClientTLS returns true if the given request is being served over secure transport.
type ClientTLS func(r *http.Request) bool

// DirectClientTLS returns true if the given HTTP request has a valid TLS connection state.
func DirectClientTLS(r *http.Request) bool {
	return r.TLS != nil
}

// ForwardedClientTLS returns true if the first X-Forwarded-Proto HTTP header is `https`.
// It returns false if the header is missing or is any other value.
func ForwardedClientTLS(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
