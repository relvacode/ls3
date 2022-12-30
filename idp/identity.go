package idp

import (
	"errors"
	"github.com/relvacode/ls3/exception"
)

const (
	// IdentityUnauthenticatedPublic is a special AccessKeyId for unauthenticated requests.
	IdentityUnauthenticatedPublic = ""
)

var ErrMissingAccessKeyId = &exception.Error{
	ErrorCode: exception.InvalidAccessKeyId,
	Message:   "The AWS access key ID that you provided does not exist in our records.",
}

type Identity struct {
	Name            string
	AccessKeyId     string
	SecretAccessKey string
	Policy          []*PolicyStatement
}

// PreAuthenticationIdentity is used in logging as the initial identity given to a new request context.
// It always denies access to all resources
var PreAuthenticationIdentity = &Identity{
	Name: "PreAuthentication",
	Policy: []*PolicyStatement{
		{
			Deny:     true,
			Resource: []Resource{"*"},
			Action:   []Action{"*"},
		},
	},
}

type Provider interface {
	// Get returns the identity associated with the provided access key ID.
	// It should return ErrMissingAccessKeyId if the given access key does not exist.
	Get(keyId string) (*Identity, error)
}

// Keyring implements Provider for a static set of identities,
// where the key is the AccessKeyId.
type Keyring map[string]*Identity

func (k Keyring) Get(keyId string) (*Identity, error) {
	id, ok := k[keyId]
	if !ok {
		return nil, ErrMissingAccessKeyId
	}

	return id, nil
}

// MultiIdentityProvider implements Provider by trying each provider in order from first to last.
// If the provider returns InvalidAccessKeyId then MultiIdentityProvider continues to the next identity.
// If there are no valid identities then ErrMissingAccessKeyId is returned.
type MultiIdentityProvider []Provider

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
