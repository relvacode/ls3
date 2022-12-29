package security

import (
	"net"
	"net/http"
)

// ClientIP provides the remote IP for an HTTP request by inspecting the contents of the request.
// The returned IP address may be an IPv4 or IPv6 address.
type ClientIP func(r *http.Request) net.IP

// DirectClientIP assumes that there is no intermediate proxy between the ls3 server and the client.
// It takes the remote IP from the connection.
// Requires that the HTTP server was set with ConnContext.
func DirectClientIP(r *http.Request) (ip net.IP) {
	conn, ok := GetConn(r.Context())
	if ok {
		switch addr := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			return addr.IP
		case *net.UDPAddr:
			return addr.IP
		}
	}

	return
}

// ForwardedRealIP takes the value of the X-Real-Ip header from the HTTP request.
// If the header is missing or does not contain a valid IP then DirectClientIP is used instead.
func ForwardedRealIP(r *http.Request) net.IP {
	fromHeader := r.Header.Get("X-Real-Ip")
	if fromHeader == "" {
		return DirectClientIP(r)
	}

	clientIP := net.ParseIP(fromHeader)
	if clientIP == nil {
		return DirectClientIP(r)
	}

	return clientIP
}
