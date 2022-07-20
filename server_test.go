package ls3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func testSignedRequest(signer Signer, method, path, query string, headers http.Header, payload []byte) *http.Request {
	req := &http.Request{
		Method: method,
		Body:   io.NopCloser(bytes.NewReader(payload)),
		Header: make(http.Header),
		URL: &url.URL{
			Host:     "testing",
			Path:     path,
			RawQuery: query,
		},
	}

	req = req.WithContext(context.Background())

	if len(headers) > 0 {
		for k, v := range headers {
			req.Header[k] = append([]string{}, v...)
		}
	}

	if len(payload) > 0 {
		req.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	}

	req.Header.Set("Host", "testing")

	h := sha256.New()
	h.Write(payload)
	req.Header.Set("x-amz-content-sha256", fmt.Sprintf("%x", h.Sum(nil)))

	t := time.Now().UTC()

	req.Header.Set("x-amz-date", t.Format(amzDateTimeFormat))

	var (
		canonicalRequest = signer.CanonicalRequest(req, h.Sum(nil), []string{"host", "x-amz-content-sha256", "x-amz-date"})
		signature        = sumHmacSha256(signer.SigningKey(t), signer.StringToSign(t, canonicalRequest))
	)

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=%x",
		signer.AccessKeyID,
		t.Format(amzDateFormat),
		signer.Region,
		signature,
	))

	return req
}

func TestServer(t *testing.T) {
	t.Run("InvalidMethod", func(t *testing.T) {
		t.Run("host_style", func(t *testing.T) {
			uid, _ := uuid.Parse("123e4567-e89b-12d3-a456-426614174000")

			rw := httptest.NewRecorder()
			srv := NewServer(zap.NewNop(), testSigner, nil, false)
			srv.uidGen = func() uuid.UUID {
				return uid
			}

			req := testSignedRequest(testSigner, http.MethodTrace, "/Path/to/Resource", "", nil, nil)
			srv.ServeHTTP(rw, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
			assert.Equal(t, "application/xml", rw.Header().Get("Content-Type"))
			assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <Resource>/Path/to/Resource</Resource>
  <RequestId>123e4567-e89b-12d3-a456-426614174000</RequestId>
</Error>`, rw.Body.String())
		})

		t.Run("path_style", func(t *testing.T) {
			uid, _ := uuid.Parse("123e4567-e89b-12d3-a456-426614174000")

			rw := httptest.NewRecorder()
			srv := NewServer(zap.NewNop(), testSigner, nil, true)
			srv.uidGen = func() uuid.UUID {
				return uid
			}

			req := testSignedRequest(testSigner, http.MethodTrace, "/bucket/Path/to/Resource", "", nil, nil)
			srv.ServeHTTP(rw, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
			assert.Equal(t, "application/xml", rw.Header().Get("Content-Type"))
			assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <Resource>/Path/to/Resource</Resource>
  <RequestId>123e4567-e89b-12d3-a456-426614174000</RequestId>
</Error>`, rw.Body.String())
		})
	})
}
