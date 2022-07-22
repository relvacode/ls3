package ls3

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func Test_checkConditionalRequest(t *testing.T) {
	obj := &Object{
		ETag:         "",
		LastModified: time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
	}

	t.Run("unconditional", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{}, obj)
		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("If-Match true", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Match": []string{""},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("If-Match false", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Match": []string{"some other etag"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusPreconditionFailed, code)
	})

	t.Run("If-None-Match true", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-None-Match": []string{"some other etag"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("If-None-Match false", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-None-Match": []string{""},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotModified, code)
	})

	t.Run("If-Modified-Since true", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Modified-Since": []string{"Sat, 02 Jan 2022 00:00:00 GMT"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("If-Modified-Since false", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Modified-Since": []string{"Thu, 31 Dec 2021 00:00:00 GMT"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotModified, code)
	})

	t.Run("If-Unmodified-Since true", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Unmodified-Since": []string{"Sat, 02 Jan 2022 00:00:00 GMT"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("If-Unmodified-Since false", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Unmodified-Since": []string{"Thu, 31 Dec 2021 00:00:00 GMT"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusPreconditionFailed, code)
	})

	t.Run("Consideration-1", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-Match":          []string{""},
			"If-Modified-Since": []string{"Sat, 02 Jan 2022 00:00:00 GMT"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	t.Run("Consideration-2", func(t *testing.T) {
		code, err := checkConditionalRequest(http.Header{
			"If-None-Match":     []string{""},
			"If-Modified-Since": []string{"Sat, 02 Jan 2022 00:00:00 GMT"},
		}, obj)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotModified, code)
	})
}
