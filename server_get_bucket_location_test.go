package ls3

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_GetBucketLocation(t *testing.T) {
	rw := httptest.NewRecorder()

	req := testSignedRequest(testSigner(), http.MethodGet, "/Bucket", "location=", nil, nil)
	testServer().ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "application/xml", rw.Header().Get("Content-Type"))
	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`, rw.Body.String())
}
