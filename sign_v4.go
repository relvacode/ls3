package ls3

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// Trim leading and trailing spaces and replace sequential spaces with one space, following Trimall()
// in http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func signV4TrimAll(input string) string {
	// Compress adjacent spaces (a space is determined by
	// unicode.IsSpace() internally here) to one space and return
	return strings.Join(strings.Fields(input), " ")
}

func awsV4CanonicalRequest(r *http.Request, hashedPayload []byte, signedHeaders []string) []byte {
	var b bytes.Buffer

	// HTTPMethod
	b.WriteString(r.Method)
	b.WriteRune('\n')

	// CanonicalURI
	b.WriteString(encodePath(r.URL.Path))
	b.WriteRune('\n')

	// CanonicalQuerystring
	b.WriteString(strings.ReplaceAll(r.URL.RawQuery, "+", "%20"))
	b.WriteRune('\n')

	// CanonicalHeaders
	for _, hdr := range signedHeaders {
		hdrName := strings.ToLower(hdr)
		b.WriteString(hdrName)
		b.WriteRune(':')

		if hdrName == "host" {
			hdrValue := r.Header.Get("Host")
			if hdrValue == "" {
				hdrValue = r.Host
			}

			b.WriteString(hdrValue)
			b.WriteRune('\n')
			continue
		}

		for idx, v := range r.Header[textproto.CanonicalMIMEHeaderKey(hdrName)] {
			if idx > 0 {
				b.WriteByte(',')
			}
			b.WriteString(signV4TrimAll(v))
		}
		b.WriteRune('\n')
	}
	b.WriteRune('\n')

	// SignedHeaders
	for i, hdr := range signedHeaders {
		if i > 0 {
			b.WriteRune(';')
		}

		b.WriteString(strings.ToLower(hdr))
	}
	b.WriteRune('\n')

	// HashedPayload
	b.WriteString(hex.EncodeToString(hashedPayload))

	return b.Bytes()
}

type SignAWSV4 struct {
	Region                string
	AccessKeyID           string
	SecretAccessKey       string
	MaxCredentialValidity time.Duration
}

func (s SignAWSV4) SigningRegion() string {
	return s.Region
}

func (s SignAWSV4) computeStringToSign(at time.Time, canonicalRequest []byte) []byte {
	var b bytes.Buffer

	b.WriteString("AWS4-HMAC-SHA256\n")

	// timeStampISO8601Format
	b.WriteString(at.Format(amzDateTimeFormat))
	b.WriteRune('\n')

	// Scope
	b.WriteString(at.Format(amzDateFormat))
	b.WriteRune('/')
	b.WriteString(s.Region)
	b.WriteString("/s3/aws4_request\n")

	// Hex(SHA256Hash(<CanonicalRequest>))
	h := sha256.New()
	h.Write(canonicalRequest)
	b.WriteString(hex.EncodeToString(h.Sum(nil)))

	return b.Bytes()
}

func (s SignAWSV4) computeSigningKey(at time.Time) []byte {
	var signed = sumHmacSha256([]byte("AWS4"+s.SecretAccessKey), at.AppendFormat(nil, amzDateFormat))
	signed = sumHmacSha256(signed, []byte(s.Region))
	signed = sumHmacSha256(signed, []byte("s3"))
	signed = sumHmacSha256(signed, []byte("aws4_request"))

	return signed
}

func (s SignAWSV4) httpHeaderAmzRequestDate(r *http.Request) (time.Time, error) {
	date := r.Header.Get("x-amz-date")
	if date == "" {
		return time.Time{}, &Error{
			ErrorCode: InvalidArgument,
			Message:   "Missing x-amz-date header.",
		}
	}

	at, err := time.Parse(amzDateTimeFormat, date)
	if err != nil {
		return time.Time{}, err
	}

	if s.MaxCredentialValidity > 0 {
		if at.Before(time.Now().Add(-s.MaxCredentialValidity)) {
			return time.Time{}, &Error{
				ErrorCode: ExpiredToken,
				Message:   "The provided token has expired.",
			}
		}
	}

	return at, nil
}

func (s SignAWSV4) Sign(r *http.Request, payload []byte) error {
	h := sha256.New()
	h.Write(payload)
	r.Header.Set("x-amz-content-sha256", fmt.Sprintf("%x", h.Sum(nil)))

	t := time.Now().UTC()

	r.Header.Set("x-amz-date", t.Format(amzDateTimeFormat))

	r.Header.Set("Host", r.Host)

	var (
		canonicalRequest = awsV4CanonicalRequest(r, h.Sum(nil), []string{"host", "x-amz-content-sha256", "x-amz-date"})
		signature        = sumHmacSha256(s.computeSigningKey(t), s.computeStringToSign(t, canonicalRequest))
	)

	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=%x",
		s.AccessKeyID,
		t.Format(amzDateFormat),
		s.Region,
		signature,
	))

	return nil
}

func (s SignAWSV4) Verify(r *http.Request) error {
	at, err := s.httpHeaderAmzRequestDate(r)
	if err != nil {
		return err
	}

	auth, err := ParseAuthorization([]byte(r.Header.Get("Authorization")))
	if err != nil {
		return &Error{
			ErrorCode: InvalidToken,
			Message:   err.Error(),
		}
	}

	// Server only supports a single set of credentials.
	// Check that the request credentials ID matches this server
	if reqCred := string(auth.Credentials.AccessKeyID); reqCred != s.AccessKeyID {
		return &Error{
			ErrorCode: InvalidAccessKeyId,
			Message:   fmt.Sprintf("The access key ID %s does not exist.", reqCred),
		}
	}

	contentShaHeader := r.Header.Get(headerXAmzContextSha256)
	if contentShaHeader == "" {
		return &Error{
			ErrorCode: MissingSecurityHeader,
			Message:   fmt.Sprintf("Your request is missing the required header %s.", headerXAmzContextSha256),
		}
	}

	contentShaRaw, _ := hex.DecodeString(contentShaHeader)

	// Read request payload
	var payload bytes.Buffer
	_, err = io.Copy(&payload, r.Body)
	closeErr := r.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return err
	}

	// After body has been read by signature verification,
	// replace the original request body with the raw payload
	r.Body = io.NopCloser(&payload)

	// Compute payload SHA256
	computedPayloadShaHasher := sha256.New()
	computedPayloadShaHasher.Write(payload.Bytes())
	computedPayloadSha := computedPayloadShaHasher.Sum(nil)

	if payload.Len() > 0 && subtle.ConstantTimeCompare(computedPayloadSha, contentShaRaw) != 1 {
		return &Error{
			ErrorCode: BadDigest,
			Message:   "The Content-MD5 or checksum value that you specified did not match what the server received.",
		}
	}

	var (
		req       = awsV4CanonicalRequest(r, computedPayloadSha, auth.SignedHeaders)
		signature = sumHmacSha256(s.computeSigningKey(at), s.computeStringToSign(at, req))
	)

	// Check request signature is equal to the computed signature
	if subtle.ConstantTimeCompare(signature, auth.Signature) != 1 {
		return &Error{
			ErrorCode: SignatureDoesNotMatch,
			Message:   "The request signature that the server calculated does not match the signature that you provided.",
		}
	}

	return nil

}
