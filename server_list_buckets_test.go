package ls3

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_ListBuckets(t *testing.T) {
	rw := httptest.NewRecorder()

	req := testSignedRequest(SignAWSV4{}, http.MethodGet, "/", "", nil, nil)
	testServer().ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "application/xml", rw.Header().Get("Content-Type"))
	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Buckets>
    <Bucket>
      <CreationDate>2022-01-01T00:00:00Z</CreationDate>
      <Name>any</Name>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>`, rw.Body.String())
}
