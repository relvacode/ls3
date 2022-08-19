package ls3

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"io"
	"testing"
	"time"
)

// TestIdentity is an Identity used in most tests,
// It uses the reference example identity in the AWS documentation.
// It allows access to any method.
var TestIdentity = &Identity{
	AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	Policy: []*PolicyStatement{
		{
			Action:   []Action{"*"},
			Resource: []Resource{"*"},
		},
	},
}

type testIdentityProvider struct{}

func (testIdentityProvider) Get(_ string) (*Identity, error) {
	return TestIdentity, nil
}

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

	fp := &FileIdentityProvider{
		open:  testOpener,
		log:   zap.NewNop(),
		cache: time.Millisecond * 500,
	}

	_, err := fp.Get("test")
	assert.NoError(t, err)
	_, err = fp.Get("nil")
	assertIsError(t, err, InvalidAccessKeyId)

	assert.Equal(t, 1, timesOpened)

	<-time.After(time.Second)

	_, err = fp.Get("test")
	assert.NoError(t, err)

	assert.Equal(t, 2, timesOpened)
}
