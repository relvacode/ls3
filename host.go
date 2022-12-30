package ls3

import (
	"github.com/relvacode/ls3/exception"
	"net"
	"net/http"
	"strings"
)

func bucketFromPath(r *http.Request) (string, bool, error) {
	pathComponents := strings.SplitN(strings.TrimLeft(r.URL.Path, "/"), "/", 2)
	var bucketName = strings.Trim(pathComponents[0], "/")

	if bucketName == "" {
		return "", false, nil
	}

	var urlPath string
	if len(pathComponents) > 1 {
		urlPath = strings.TrimLeft(pathComponents[1], "/")
	}

	r.URL.Path = "/" + urlPath

	return bucketName, true, nil
}

func bucketFromRequest(r *http.Request, domain []string) (string, bool, error) {
	if len(domain) == 0 {
		return bucketFromPath(r)
	}

	// Best effort to get the bucket name from the URL host.
	// Take the lowest domain components of the request host.
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}

	hostComponents := strings.Split(host, ".")
	if len(hostComponents) < len(domain) {
		return "", false, &exception.Error{
			ErrorCode: exception.InvalidRequest,
			Message:   "Invalid request hostname.",
		}
	}

	// Check that all the host components match up with the server domain
	i := len(domain) - 1
	j := len(hostComponents) - 1

	for i >= 0 {
		if domain[i] != hostComponents[j] {
			return "", false, &exception.Error{
				ErrorCode: exception.InvalidRequest,
				Message:   "The requested hostname is not recognised.",
			}
		}

		i--
		j--
	}

	switch len(hostComponents) {
	case len(domain):
		// Request is for the base domain, so use path-style addressing
		return bucketFromPath(r)
	case len(domain) + 1:
		// Request is for the base domain + 1, so use host-style addressing
		return hostComponents[0], true, nil
	default:
		// Too many components in host domain
		return "", false, &exception.Error{
			ErrorCode: exception.InvalidRequest,
			Message:   "Invalid request hostname.",
		}
	}
}
