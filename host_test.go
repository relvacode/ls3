package ls3

import (
	"errors"
	"github.com/relvacode/ls3/exception"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func Test_bucketFromRequest(t *testing.T) {
	t.Run("path", func(t *testing.T) {
		req := &http.Request{
			URL: &url.URL{
				Path: "/bucket/",
			},
		}

		bucket, ok, err := bucketFromRequest(req, nil)
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "bucket", bucket)
	})

	t.Run("path_key", func(t *testing.T) {
		req := &http.Request{
			URL: &url.URL{
				Path: "/bucket/key",
			},
		}

		bucket, ok, err := bucketFromRequest(req, nil)
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "bucket", bucket)
	})

	t.Run("path_no_path", func(t *testing.T) {
		req := &http.Request{
			URL: &url.URL{
				Path: "/",
			},
		}

		_, ok, err := bucketFromRequest(req, nil)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("host", func(t *testing.T) {
		req := &http.Request{
			Host: "bucket.domain:80",
			URL: &url.URL{
				Path: "/",
			},
		}

		bucket, ok, err := bucketFromRequest(req, []string{"domain"})
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "bucket", bucket)
	})

	t.Run("host_nested", func(t *testing.T) {
		req := &http.Request{
			Host: "bucket.domain.net:80",
			URL: &url.URL{
				Path: "/",
			},
		}

		bucket, ok, err := bucketFromRequest(req, []string{"domain", "net"})
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "bucket", bucket)
	})

	t.Run("host_no_bucket", func(t *testing.T) {
		req := &http.Request{
			Host: "domain:80",
			URL: &url.URL{
				Path: "/bucket/",
			},
		}

		bucket, ok, err := bucketFromRequest(req, []string{"domain"})
		assert.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "bucket", bucket)
	})

	t.Run("host_no_bucket_no_path", func(t *testing.T) {
		req := &http.Request{
			Host: "domain:80",
			URL: &url.URL{
				Path: "/",
			},
		}

		_, ok, err := bucketFromRequest(req, []string{"domain"})
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("host_wrong_base_domain", func(t *testing.T) {
		req := &http.Request{
			Host: "incorrect:80",
			URL: &url.URL{
				Path: "/",
			},
		}

		_, ok, err := bucketFromRequest(req, []string{"domain"})
		assert.Error(t, err)
		assert.False(t, ok)
		assert.True(t, errors.Is(err, &exception.Error{ErrorCode: exception.InvalidRequest}))
	})

	t.Run("host_not_enough_components", func(t *testing.T) {
		req := &http.Request{
			Host: "domain:80",
			URL: &url.URL{
				Path: "/",
			},
		}

		_, ok, err := bucketFromRequest(req, []string{"domain", "net"})
		assert.Error(t, err)
		assert.False(t, ok)
		assert.True(t, errors.Is(err, &exception.Error{ErrorCode: exception.InvalidRequest}))
	})

	t.Run("host_not_intersect_components", func(t *testing.T) {
		req := &http.Request{
			Host: "base.domain:80",
			URL: &url.URL{
				Path: "/",
			},
		}

		_, ok, err := bucketFromRequest(req, []string{"domain", "net"})
		assert.Error(t, err)
		assert.False(t, ok)
		assert.True(t, errors.Is(err, &exception.Error{ErrorCode: exception.InvalidRequest}))
	})
}
