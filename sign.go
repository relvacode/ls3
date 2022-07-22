package ls3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	amzDateTimeFormat = "20060102T150405Z"
	amzDateFormat     = "20060102"
)

// A Signer is a type capable of signing and verifying the authorization and request signature present in an HTTP request.
type Signer interface {
	// SigningRegion returns the region string that is used to verify requests.
	SigningRegion() string

	// Sign computes and signs the given HTTP request using the given request payload.
	// payload should be the contents of r.Body.
	Sign(r *http.Request, payload []byte) error

	// Verify verifies the authorization and request signature present in the HTTP request.
	// Verify should return a non-nil error on verification failure, ideally this should contain the underlying type *Error.
	// If Verify reads data from r.Body, it must ensure that the data can be re-read from r if Verify returns a nil error.
	Verify(r *http.Request) error
}

func sumHmacSha256(secret, data []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)

	return h.Sum(nil)
}

func encodePath(pathName string) string {
	var encodedPathname strings.Builder
	for _, s := range pathName {
		if 'A' <= s && s <= 'Z' || 'a' <= s && s <= 'z' || '0' <= s && s <= '9' { // §2.3 Unreserved characters (mark)
			encodedPathname.WriteRune(s)
			continue
		}
		switch s {
		case '-', '_', '.', '~', '/': // §2.3 Unreserved characters (mark)
			encodedPathname.WriteRune(s)
			continue
		default:
			l := utf8.RuneLen(s)
			if l < 0 {
				// if utf8 cannot convert return the same string as is
				return pathName
			}
			u := make([]byte, l)
			utf8.EncodeRune(u, s)
			for _, r := range u {
				hexEncoded := hex.EncodeToString([]byte{r})
				encodedPathname.WriteString("%" + strings.ToUpper(hexEncoded))
			}
		}
	}
	return encodedPathname.String()
}
