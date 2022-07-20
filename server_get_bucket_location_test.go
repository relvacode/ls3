package ls3

import (
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_GetBucketLocation(t *testing.T) {
	rw := httptest.NewRecorder()
	srv := NewServer(zap.NewNop(), Signer{
		AccessKeyID:     "0123456789",
		SecretAccessKey: "0123456789",
		Region:          "eu-west-2",
	}, nil, false)

	req := testSignedRequest(srv.signer, http.MethodGet, "", "location=", nil, nil)
	srv.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "application/xml", rw.Header().Get("Content-Type"))
	assert.Equal(t, `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint>
  <LocationConstraint></LocationConstraint>
</LocationConstraint>`, rw.Body.String())
}
