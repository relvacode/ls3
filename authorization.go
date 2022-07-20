package ls3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

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

type WrappedError struct {
	Cause error
}

func (e WrappedError) Unwrap() error { return e.Cause }

type ErrInvalidCredential struct {
	WrappedError
}

func (e *ErrInvalidCredential) Error() string {
	return fmt.Sprintf("invalid credential: %s", e.Cause)
}

func ParseCredential(value []byte) (*Credential, error) {
	var credentialParts = bytes.Split(value, []byte{'/'})
	if len(credentialParts) != 5 {
		return nil, &ErrInvalidCredential{
			WrappedError: WrappedError{
				Cause: fmt.Errorf("wrong number of credential components (%d given where %d was expected", len(credentialParts), 5),
			},
		}
	}

	var credential = new(Credential)
	credential.AccessKeyID = credentialParts[0]

	var err error
	credential.Date, err = time.Parse(amzDateFormat, string(credentialParts[1]))
	if err != nil {
		return nil, &ErrInvalidCredential{
			WrappedError: WrappedError{
				Cause: err,
			},
		}
	}

	credential.Region = credentialParts[2]
	credential.Service = credentialParts[3]
	credential.Method = credentialParts[4]

	return credential, nil
}

type Credential struct {
	AccessKeyID []byte
	Date        time.Time
	Region      []byte
	Service     []byte
	Method      []byte
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
	b = append(b, c.Method...)

	return b
}

type ErrInvalidAuthorizationHeader struct {
	WrappedError
}

func (e *ErrInvalidAuthorizationHeader) Error() string {
	return fmt.Sprintf("invalid authorization header: %s", e.Cause)
}

// ParseAuthorization parses the contents of the given Authorization header.
// Returns a non-nil *ErrInvalidAuthorizationHeader when an invalid header is given.
func ParseAuthorization(hdr []byte) (*Authorization, error) {
	var auth = new(Authorization)

	var methodParts = bytes.SplitN(hdr, []byte{' '}, 2)
	if len(methodParts) < 2 {
		return nil, &ErrInvalidAuthorizationHeader{
			WrappedError: WrappedError{
				Cause: errors.New("not missing authorization properties"),
			},
		}
	}

	auth.Method = methodParts[0]

	var requestOptions = bytes.Split(methodParts[1], []byte{','})
	for i, opt := range requestOptions {
		var optionParts = bytes.SplitN(bytes.TrimSpace(opt), []byte{'='}, 2)
		if len(optionParts) < 2 {
			return nil, &ErrInvalidAuthorizationHeader{
				WrappedError: WrappedError{
					Cause: fmt.Errorf("missing key=value in header property %d", i),
				},
			}
		}

		var (
			key   = string(optionParts[0])
			value = optionParts[1]
		)

		// Unrecognised options are ignored
		switch key {
		case "Credential":
			cr, err := ParseCredential(value)
			if err != nil {
				return nil, &ErrInvalidAuthorizationHeader{
					WrappedError: WrappedError{
						Cause: err,
					},
				}
			}

			auth.Credentials = *cr
		case "SignedHeaders":
			auth.SignedHeaders = strings.Split(string(value), ";")
		case "Signature":
			auth.Signature = make([]byte, hex.DecodedLen(len(value)))
			_, err := hex.Decode(auth.Signature, value)
			if err != nil {
				return nil, &ErrInvalidAuthorizationHeader{
					WrappedError: WrappedError{
						Cause: err,
					},
				}
			}
		}
	}

	return auth, nil
}

type Authorization struct {
	Method        []byte
	Credentials   Credential
	SignedHeaders []string
	Signature     []byte // raw decoded hex
}

func (a Authorization) AppendFormat(b []byte) []byte {
	b = append(b, a.Method...)
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
