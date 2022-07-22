package ls3

import (
	"encoding/hex"
	"strings"
	"time"
)

const awsSignatureVersionV4 = "AWS4-HMAC-SHA256"

// growSlice grows slice b to length n.
// If cap(b) < n then a new slice is allocated and the original contents are copied into it
func growSlice(b []byte, n int) []byte {
	if len(b)+n <= cap(b) {
		return b[:len(b)+n]
	}

	grow := make([]byte, len(b)+n)
	copy(grow, b)

	return grow
}

func ParseCredential(value string) (*Credential, error) {
	var credentialParts = strings.Split(value, "/")
	if len(credentialParts) != 5 {
		return nil, &Error{
			ErrorCode: InvalidSecurity,
			Message:   "The provided security credentials are not valid.",
		}
	}

	var credential = new(Credential)
	credential.AccessKeyID = credentialParts[0]

	var err error
	credential.Date, err = time.Parse(amzDateFormat, credentialParts[1])
	if err != nil {
		return nil, &Error{
			ErrorCode: InvalidSecurity,
			Message:   "The provided security credentials are not valid.",
		}
	}

	credential.Region = credentialParts[2]
	credential.Service = credentialParts[3]
	credential.Type = credentialParts[4]

	return credential, nil
}

type Credential struct {
	AccessKeyID string
	Date        time.Time
	Region      string
	Service     string
	Type        string
}

func (c Credential) AppendFormat(b []byte) []byte {
	b = append(b, c.AccessKeyID...)
	b = append(b, '/')
	b = c.Date.AppendFormat(b, amzDateFormat)
	b = append(b, '/')
	b = append(b, c.Region...)
	b = append(b, '/')
	b = append(b, c.Service...)
	b = append(b, '/')
	b = append(b, c.Type...)

	return b
}

// ParseAuthorizationHeader parses the contents of the given Authorization header.
// Returns a non-nil *ErrInvalidAuthorizationHeader when an invalid header is given.
func ParseAuthorizationHeader(hdr string) (*Authorization, error) {
	var auth = new(Authorization)

	var methodParts = strings.SplitN(hdr, " ", 2)
	if len(methodParts) < 2 || methodParts[0] != awsSignatureVersionV4 {
		return nil, &Error{
			ErrorCode: InvalidRequest,
			Message:   "The request is using the wrong signature version. Use AWS4-HMAC-SHA256 (Signature Version 4).",
		}
	}

	var requestOptions = strings.Split(methodParts[1], ",")
	for _, opt := range requestOptions {
		var optionParts = strings.SplitN(strings.TrimSpace(opt), "=", 2)
		if len(optionParts) < 2 {
			return nil, &Error{
				ErrorCode: AuthorizationHeaderMalformed,
				Message:   "The authorization header that you provided is not valid.",
			}
		}

		var (
			key   = optionParts[0]
			value = optionParts[1]
		)

		// Unrecognised options are ignored
		switch key {
		case "Credential":
			cr, err := ParseCredential(value)
			if err != nil {
				return nil, &Error{
					ErrorCode: AuthorizationHeaderMalformed,
					Message:   "The authorization header that you provided is not valid.",
				}
			}

			auth.Credentials = *cr
		case "SignedHeaders":
			auth.SignedHeaders = strings.Split(value, ";")
		case "Signature":
			var err error
			auth.Signature, err = hex.DecodeString(value)
			if err != nil {
				return nil, &Error{
					ErrorCode: AuthorizationHeaderMalformed,
					Message:   "The authorization header that you provided is not valid.",
				}
			}
		}
	}

	return auth, nil
}

type Authorization struct {
	Credentials   Credential
	SignedHeaders []string
	Signature     []byte // raw decoded hex
}

func (a Authorization) AppendFormat(b []byte) []byte {
	b = append(b, awsSignatureVersionV4...)
	b = append(b, ' ')
	b = append(b, "Credential="...)
	b = a.Credentials.AppendFormat(b)
	b = append(b, ",SignedHeaders="...)

	for i, hdr := range a.SignedHeaders {
		if i > 0 {
			b = append(b, ';')
		}
		b = append(b, hdr...)
	}

	b = append(b, ",Signature="...)
	l := len(b)
	b = growSlice(b, hex.EncodedLen(len(a.Signature)))
	hex.Encode(b[l:], a.Signature)

	return b
}
