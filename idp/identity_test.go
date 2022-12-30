package idp

import (
	"bytes"
	"errors"
	"github.com/relvacode/ls3/exception"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"io"
	"testing"
	"time"
)

func TestMultiIdentityProvider_Get(t *testing.T) {
	var ring1 = Keyring{
		"Ring1": &Identity{
			Name: "Ring1",
		},
	}
	var ring2 = Keyring{
		"Ring2": &Identity{
			Name: "Ring2",
		},
	}

	var mp = MultiIdentityProvider{ring1, ring2}

	id, err := mp.Get("Ring1")
	assert.NoError(t, err)
	assert.Equal(t, "Ring1", id.Name)

	id, err = mp.Get("Ring2")
	assert.NoError(t, err)
	assert.Equal(t, "Ring2", id.Name)
}

func TestFileIdentityProvider_Get(t *testing.T) {
	var testFile = []byte(`[
{"Name": "Test", "AccessKeyId": "test", "SecretAccessKey": "test"}
]`)

	var timesOpened int
	var testOpener = func() (io.ReadCloser, error) {
		timesOpened++
		return io.NopCloser(bytes.NewReader(testFile)), nil
	}

	fp := &FileProvider{
		open:  testOpener,
		log:   zap.NewNop(),
		cache: time.Millisecond * 500,
	}

	_, err := fp.Get("test")
	assert.NoError(t, err)
	_, err = fp.Get("nil")

	assert.True(t, errors.Is(err, &exception.Error{ErrorCode: exception.InvalidAccessKeyId}))
	assert.Equal(t, 1, timesOpened)

	<-time.After(time.Second)

	_, err = fp.Get("test")
	assert.NoError(t, err)

	assert.Equal(t, 2, timesOpened)
}
