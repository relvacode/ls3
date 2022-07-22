package ls3

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_HeadBucket(t *testing.T) {
	rw := httptest.NewRecorder()

	req := testSignedRequest(testSigner(), http.MethodHead, "/Bucket", "", nil, nil)
	testServer().ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, testSigner().Region, rw.Header().Get("x-amz-bucket-region"))
}
