package ls3

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/psanford/memfs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func testServer() *Server {
	srv := NewServer(zap.NewNop(), testSigner, SingleBucketFilesystem(memfs.New()), "")
	uid, _ := uuid.Parse("123e4567-e89b-12d3-a456-426614174000")
	srv.uidGen = func() uuid.UUID {
		return uid
	}

	return srv
}

func testSignedRequest(signer Signer, method, path, query string, headers http.Header, payload []byte) *http.Request {
	req := &http.Request{
		Method: method,
		Host:   "bucket.testing:80",
		Body:   io.NopCloser(bytes.NewReader(payload)),
		Header: make(http.Header),
		URL: &url.URL{
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

	_ = signer.Sign(req, payload)

	return req
}

func TestServer(t *testing.T) {
	t.Run("InvalidMethod", func(t *testing.T) {
		t.Run("host_style", func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := testSignedRequest(testSigner, http.MethodTrace, "/Path/to/Resource", "", nil, nil)

			srv := testServer()
			srv.domain = []string{"testing"}
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
			rw := httptest.NewRecorder()
			req := testSignedRequest(testSigner, http.MethodTrace, "/bucket/Path/to/Resource", "", nil, nil)
			testServer().ServeHTTP(rw, req)

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
