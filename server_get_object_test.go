package ls3

import (
	"github.com/relvacode/ls3/exception"
	"github.com/relvacode/ls3/idp"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_GetObject(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		t.Run("with_bucket_access", func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := testSignedRequest(SignAWSV4{}, http.MethodGet, "/bucket/object.txt", "", nil, nil)
			testServer().ServeHTTP(rw, req)

			AssertIsResponseError(t, rw, exception.NoSuchKey)
		})

		t.Run("without_bucket_access", func(t *testing.T) {
			rw := httptest.NewRecorder()
			req := testSignedRequest(SignAWSV4{}, http.MethodGet, "/bucket/object.txt", "", nil, nil)

			denyBucketAccess := idp.PolicyStatement{
				Deny:     true,
				Action:   idp.OptionalList[idp.Action]{idp.ListBucket},
				Resource: idp.OptionalList[idp.Resource]{"*"},
			}
			testServer(&denyBucketAccess).ServeHTTP(rw, req)

			AssertIsResponseError(t, rw, exception.AccessDenied)
		})
	})
}
