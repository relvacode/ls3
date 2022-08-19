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
	"strconv"
	"strings"
	"time"
)

const (
	amzUnsignedPayload = "UNSIGNED-PAYLOAD"
	xAmzCredential     = "X-Amz-Credential"
	xAmzAlgorithm      = "X-Amz-Algorithm"
	xAmzDate           = "X-Amz-Date"
	xAmzContextSha256  = "x-Amz-Content-Sha256"
	xAmzExpires        = "X-Amz-Expires"
	xAmzSignedHeaders  = "X-Amz-SignedHeaders"
	xAmzSignature      = "X-Amz-Signature"
)

const (
	minimumPresignedExpires = time.Second
	maximumPresignedExpiry  = time.Second * 604800
)

// Trim leading and trailing spaces and replace sequential spaces with one space, following Trimall()
// in http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func signV4TrimAll(input string) string {
	// Compress adjacent spaces (a space is determined by
	// unicode.IsSpace() internally here) to one space and return
	return strings.Join(strings.Fields(input), " ")
}

func payloadSha256Hex(r *http.Request, contentSha256 string) ([]byte, error) {
	switch contentSha256 {
	case "", amzUnsignedPayload:
		return []byte(amzUnsignedPayload), nil
	default:
		contentShaRaw, _ := hex.DecodeString(contentSha256)

		// Read request payload
		var payload bytes.Buffer
		_, err := io.Copy(&payload, r.Body)
		closeErr := r.Body.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}

		// After body has been read by signature verification,
		// replace the original request body with the raw payload
		r.Body = io.NopCloser(&payload)

		// Compute payload SHA256
		computedPayloadShaHasher := sha256.New()
		computedPayloadShaHasher.Write(payload.Bytes())
		computedPayloadSha := computedPayloadShaHasher.Sum(nil)

		if payload.Len() > 0 && subtle.ConstantTimeCompare(computedPayloadSha, contentShaRaw) != 1 {
			return nil, &Error{
				ErrorCode: BadDigest,
				Message:   "The Content-MD5 or checksum value that you specified did not match what the server received.",
			}
		}

		var payloadShaHex = make([]byte, hex.EncodedLen(len(computedPayloadSha)))
		hex.Encode(payloadShaHex, computedPayloadSha)
		return payloadShaHex, nil
	}
}

func awsV4CanonicalRequest(r *http.Request, payloadShaHex []byte, signedHeaders []string) []byte {
	var b bytes.Buffer

	// HTTPMethod
	b.WriteString(r.Method)
	b.WriteRune('\n')

	// CanonicalURI
	b.WriteString(encodePath(r.URL.Path))
	b.WriteRune('\n')

	// CanonicalQuerystring
	// Query string must be decoded, and then re-encoded to sort the query keys.
	var urlQuery = r.URL.Query()

	// Delete the signature from the query, as it is not part of the signature calculation
	urlQuery.Del(xAmzSignature)

	b.WriteString(strings.ReplaceAll(urlQuery.Encode(), "+", "%20"))
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
	b.Write(payloadShaHex)

	return b.Bytes()
}

var _ Signer = (*SignAWSV4)(nil)

type SignAWSV4 struct {
	// timeNow is a function that returns the current time.
	// Used for testing, if nil then time.Now is used.
	timeNow func() time.Time
}

func (s SignAWSV4) now() time.Time {
	if s.timeNow == nil {
		return time.Now()
	}
	return s.timeNow()
}

func (s SignAWSV4) computeStringToSign(at time.Time, region string, canonicalRequest []byte) []byte {
	var b bytes.Buffer

	b.WriteString(awsSignatureVersionV4)
	b.WriteRune('\n')

	// timeStampISO8601Format
	b.WriteString(at.Format(amzDateTimeFormat))
	b.WriteRune('\n')

	// Scope
	b.WriteString(at.Format(amzDateFormat))
	b.WriteRune('/')
	b.WriteString(region)
	b.WriteString("/s3/aws4_request\n")

	// Hex(SHA256Hash(<CanonicalRequest>))
	h := sha256.New()
	h.Write(canonicalRequest)
	hex.NewEncoder(&b).Write(h.Sum(nil))

	return b.Bytes()
}

func (s SignAWSV4) computeSigningKey(at time.Time, region string, identity *Identity) []byte {
	var signed = sumHmacSha256([]byte("AWS4"+identity.SecretAccessKey), at.AppendFormat(nil, amzDateFormat))
	signed = sumHmacSha256(signed, []byte(region))
	signed = sumHmacSha256(signed, []byte("s3"))
	signed = sumHmacSha256(signed, []byte("aws4_request"))

	return signed
}

func (s SignAWSV4) Sign(r *http.Request, identity *Identity, payload []byte) error {
	h := sha256.New()
	h.Write(payload)
	r.Header.Set(xAmzContextSha256, fmt.Sprintf("%x", h.Sum(nil)))

	t := s.now().UTC()

	r.Header.Set(xAmzDate, t.Format(amzDateTimeFormat))

	r.Header.Set("Host", r.Host)

	var computedPayloadSha = h.Sum(nil)
	var payloadShaHex = make([]byte, hex.EncodedLen(len(computedPayloadSha)))
	hex.Encode(payloadShaHex, computedPayloadSha)

	var (
		canonicalRequest = awsV4CanonicalRequest(r, payloadShaHex, []string{"host", "x-amz-content-sha256", "x-amz-date"})
		signature        = sumHmacSha256(s.computeSigningKey(t, "us-east-1", identity), s.computeStringToSign(t, "us-east-1", canonicalRequest))
	)

	r.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=%x",
		awsSignatureVersionV4,
		identity.AccessKeyId,
		t.Format(amzDateFormat),
		signature,
	))

	return nil
}

func (s SignAWSV4) VerifyHeaders(r *http.Request, provider IdentityProvider) (*Identity, error) {
	date := r.Header.Get(xAmzDate)
	if date == "" {
		return nil, &Error{
			ErrorCode: InvalidArgument,
			Message:   "Missing x-amz-date header.",
		}
	}

	at, err := time.Parse(amzDateTimeFormat, date)
	if err != nil {
		return nil, &Error{
			ErrorCode: InvalidRequest,
			Message:   "Invalid format of X-Amz-Date.",
		}
	}

	auth, err := ParseAuthorizationHeader(r.Header.Get("Authorization"))
	if err != nil {
		return nil, &Error{
			ErrorCode: InvalidToken,
			Message:   err.Error(),
		}
	}

	identity, err := provider.Get(auth.Credentials.AccessKeyID)
	if err != nil {
		return nil, err
	}

	payloadShaHex, err := payloadSha256Hex(r, r.Header.Get(xAmzContextSha256))
	if err != nil {
		return nil, err
	}

	var (
		req       = awsV4CanonicalRequest(r, payloadShaHex, auth.SignedHeaders)
		signature = sumHmacSha256(s.computeSigningKey(at, auth.Credentials.Region, identity), s.computeStringToSign(at, auth.Credentials.Region, req))
	)

	// Check request signature is equal to the computed signature
	if subtle.ConstantTimeCompare(signature, auth.Signature) != 1 {
		return nil, &Error{
			ErrorCode: SignatureDoesNotMatch,
			Message:   "The request signature that the server calculated does not match the signature that you provided.",
		}
	}

	return identity, nil
}

func (s SignAWSV4) VerifyQuery(r *http.Request, provider IdentityProvider) (*Identity, error) {
	var q = r.URL.Query()

	if queryAlgorithm := q.Get(xAmzAlgorithm); queryAlgorithm != awsSignatureVersionV4 {
		return nil, &Error{
			ErrorCode: InvalidRequest,
			Message:   "The request is using the wrong signature version. Use AWS4-HMAC-SHA256 (Signature Version 4).",
		}
	}

	date := q.Get(xAmzDate)
	if date == "" {
		return nil, &Error{
			ErrorCode: InvalidArgument,
			Message:   "Missing x-amz-date header.",
		}
	}

	at, err := time.Parse(amzDateTimeFormat, date)
	if err != nil {
		return nil, &Error{
			ErrorCode: InvalidRequest,
			Message:   "Invalid format of X-Amz-Date.",
		}
	}

	// Check that the pre-signed request has not expired
	expiresInt, _ := strconv.Atoi(q.Get(xAmzExpires))
	expires := time.Second * time.Duration(expiresInt)

	if expires < minimumPresignedExpires || expires > maximumPresignedExpiry {
		return nil, &Error{
			ErrorCode: InvalidRequest,
			Message:   "Invalid value for X-Amz-Expires.",
		}
	}

	if s.now().After(at.Add(expires)) {
		return nil, &Error{
			ErrorCode: ExpiredToken,
			Message:   "The provided token has expired.",
		}
	}

	// Parse credentials from the credential parameter
	credential, err := ParseCredential(q.Get(xAmzCredential))
	if err != nil {
		return nil, err
	}

	identity, err := provider.Get(credential.AccessKeyID)
	if err != nil {
		return nil, err
	}

	// We can ignore any errors or length to the request signature.
	// An invalid signature will not match the computed signature
	requestSignature, _ := hex.DecodeString(q.Get(xAmzSignature))

	// Compute the payload SHA256 hex of the request
	payloadShaHex, err := payloadSha256Hex(r, q.Get(xAmzContextSha256))
	if err != nil {
		return nil, err
	}

	var (
		req       = awsV4CanonicalRequest(r, payloadShaHex, q[xAmzSignedHeaders])
		signature = sumHmacSha256(s.computeSigningKey(at, credential.Region, identity), s.computeStringToSign(at, credential.Region, req))
	)

	// Check request signature is equal to the computed signature
	if subtle.ConstantTimeCompare(signature, requestSignature) != 1 {
		return nil, &Error{
			ErrorCode: SignatureDoesNotMatch,
			Message:   "The request signature that the server calculated does not match the signature that you provided.",
		}
	}

	return identity, nil
}

func (s SignAWSV4) Verify(r *http.Request, provider IdentityProvider) (*Identity, error) {
	// If X-Amz-Algorithm is provided in the request then use query parameter based authorization
	if r.URL.Query().Get(xAmzAlgorithm) != "" {
		return s.VerifyQuery(r, provider)
	}

	return s.VerifyHeaders(r, provider)
}
