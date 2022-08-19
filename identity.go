package ls3

import (
	"encoding/json"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"io"
	"os"
	"sync"
	"time"
)

const (
	// IdentityUnauthenticatedPublic is a special AccessKeyId for unauthenticated requests.
	IdentityUnauthenticatedPublic = ""
)

var ErrMissingAccessKeyId = &Error{
	ErrorCode: InvalidAccessKeyId,
	Message:   "The AWS access key ID that you provided does not exist in our records.",
}

type Identity struct {
	Name            string
	AccessKeyId     string
	SecretAccessKey string
	Policy          []*PolicyStatement
}

type IdentityProvider interface {
	// Get returns the identity associated with the provided access key ID.
	// It should return ErrMissingAccessKeyId if the given access key does not exist.
	Get(keyId string) (*Identity, error)
}

// Keyring implements IdentityProvider for a static set of identities,
// where the key is the AccessKeyId.
type Keyring map[string]*Identity

func (k Keyring) Get(keyId string) (*Identity, error) {
	id, ok := k[keyId]
	if !ok {
		return nil, ErrMissingAccessKeyId
	}

	return id, nil
}

// MultiIdentityProvider implements IdentityProvider by trying each provider in order from first to last.
// If the provider returns InvalidAccessKeyId then MultiIdentityProvider continues to the next identity.
// If there are no valid identities then ErrMissingAccessKeyId is returned.
type MultiIdentityProvider []IdentityProvider

func (mp MultiIdentityProvider) Get(keyId string) (*Identity, error) {
	for _, provider := range mp {
		identity, err := provider.Get(keyId)
		if err == nil {
			return identity, nil
		}
		if errors.Is(err, ErrMissingAccessKeyId) {
			continue
		}
		return nil, err
	}

	return nil, ErrMissingAccessKeyId
}

func NewFileIdentityProvider(log *zap.Logger, path string, cache time.Duration) (*FileIdentityProvider, error) {
	fp := &FileIdentityProvider{
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

// FileIdentityProvider implements ls3.IdentityProvider by reading from a single JSON file.
// The file is cached for up to the configured amount of time.
type FileIdentityProvider struct {
	open  func() (io.ReadCloser, error)
	log   *zap.Logger
	cache time.Duration

	mx      sync.RWMutex
	expires time.Time
	keyring Keyring
}

// load an identity keyring from the file.
// It does not lock the provider.
func (fp *FileIdentityProvider) load() (Keyring, error) {
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

func (fp *FileIdentityProvider) Get(keyId string) (*Identity, error) {
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
		return nil, &Error{
			ErrorCode: AccountProblem,
			Message:   "There is a problem with the server credentials store that prevents the operation from completing successfully.",
		}
	}

	fp.keyring = keyring
	fp.expires = time.Now().Add(fp.cache)

	return fp.keyring.Get(keyId)
}
