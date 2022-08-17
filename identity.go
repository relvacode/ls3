package ls3

type Identity struct {
	AccessKeyID     string
	SecretAccessKey string
	ACL             []*Policy
}

type IdentityProvider interface {
	// Get returns the identity associated with the provided access key ID.
	Get(keyId string) (*Identity, error)
}

// Keyring implements IdentityProvider for a static set of identities,
// where the key is the AccessKeyID.
type Keyring map[string]*Identity

func (k Keyring) Get(keyId string) (*Identity, error) {
	id, ok := k[keyId]
	if !ok {
		return nil, &Error{
			ErrorCode: InvalidAccessKeyId,
			Message:   "The AWS access key ID that you provided does not exist in our records.",
		}
	}

	return id, nil
}
