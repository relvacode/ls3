package idp

import (
	"encoding/json"
	"fmt"
	"github.com/relvacode/ls3/exception"
	"go.uber.org/zap"
	"io"
	"os"
	"sync"
	"time"
)

func NewFileProvider(log *zap.Logger, path string, cache time.Duration) (*FileProvider, error) {
	fp := &FileProvider{
		open: func() (io.ReadCloser, error) {
			return os.Open(path)
		},
		log:   log,
		cache: cache,
	}

	keyring, err := fp.load()
	if err != nil {
		return nil, err
	}

	fp.keyring = keyring
	fp.expires = time.Now().Add(cache)

	return fp, nil
}

// FileProvider implements Provider by reading from a single JSON file.
// The file is cached for up to the configured amount of time.
type FileProvider struct {
	open  func() (io.ReadCloser, error)
	log   *zap.Logger
	cache time.Duration

	mx      sync.RWMutex
	expires time.Time
	keyring Keyring
}

// load an identity keyring from the file.
// It does not lock the provider.
func (fp *FileProvider) load() (Keyring, error) {
	r, err := fp.open()
	if err != nil {
		return nil, err
	}

	defer r.Close()

	var identities []Identity
	err = json.NewDecoder(r).Decode(&identities)
	if err != nil {
		return nil, err
	}

	var keyring = make(Keyring, len(identities))
	for i, identity := range identities {
		_, ok := keyring[identity.AccessKeyId]
		if ok {
			return nil, fmt.Errorf("identity %d (%s): multiple identities with the same AccessKeyId", i, identity.AccessKeyId)
		}

		keyring[identity.AccessKeyId] = &identity
	}

	return keyring, nil
}

func (fp *FileProvider) Get(keyId string) (*Identity, error) {
	fp.mx.RLock()
	if time.Now().Before(fp.expires) {
		defer fp.mx.RUnlock()
		return fp.keyring.Get(keyId)
	}

	fp.mx.RUnlock()

	fp.mx.Lock()
	defer fp.mx.Unlock()

	if time.Now().Before(fp.expires) {
		return fp.keyring.Get(keyId)
	}

	keyring, err := fp.load()
	if err != nil {
		fp.log.Error("failed to load new keyring", zap.Error(err))
		return nil, &exception.Error{
			ErrorCode: exception.AccountProblem,
			Message:   "There is a problem with the server credentials store that prevents the operation from completing successfully.",
		}
	}

	fp.keyring = keyring
	fp.expires = time.Now().Add(fp.cache)

	return fp.keyring.Get(keyId)
}
