package ls3

import (
	"bytes"
	"encoding/json"
)

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

type Action string

const (
	GetObject         Action = "s3:GetObject"
	ListAllMyBuckets  Action = "s3:ListAllMyBuckets"
	ListBucket        Action = "s3:ListBucket"
	GetBucketLocation Action = "s3:GetBucketLocation"
)

type Resource string

func WildcardMatch[T ~string](rule, obj T) bool {
	if len(rule) == 0 || len(obj) == 0 {
		return false
	}

	// Wildcard any
	if rule == "*" {
		return true
	}

	// Exact match
	if rule == obj {
		return true
	}

	// Rule exceeds length of obj.
	// Impossible for rule to match obj.
	if len(rule) > len(obj) {
		return false
	}

	// Wildcard search
	var x int
	var z int

scan:
	for ; x < len(rule) && z < len(obj); x, z = x+1, z+1 {
		switch chr := rule[x]; chr {
		case '?':
			// Single token match
		case '*':
			// Wildcard match
			x++
			if x == len(rule) {
				// Wildcard matches remaining object
				return true
			}

			next := rule[x]
			switch next {
			case '*', '?':
				// Wildcard rule cannot have contiguous wildcard characters
				return false
			}

			// Scan object until next token is found
			for ; z < len(obj); z++ {
				// Match for next token
				if obj[z] == next {
					continue scan
				}
			}

			// Obj scanned entirely, no match was found
			return false
		default:
			// Exact match
			if chr != obj[z] {
				return false
			}
		}
	}

	return true
}

// OptionalList provides JSON unmarshalling for a slice of objects of type T.
// T may not be itself a list.
// If the JSON object is a list or 'null', then the contents is assumed to be a list of T,
// otherwise it is a single T.
type OptionalList[T any] []T

func (l *OptionalList[T]) UnmarshalJSON(b []byte) error {
	if len(b) > 2 && b[0] == '[' && b[len(b)-1] == ']' {
		return json.Unmarshal(b, (*[]T)(l))
	}

	if bytes.Equal(b, []byte{'n', 'u', 'l', 'l'}) {
		*l = nil
		return nil
	}

	var one T
	err := json.Unmarshal(b, &one)
	if err != nil {
		return err
	}

	*l = OptionalList[T]{one}
	return nil
}

type Policy struct {
	// Deny marks this policy as an explicit deny.
	Deny bool
	// Action one or more actions that this policy applies to.
	Action OptionalList[Action]
	// Resource is one or more resources that this policy applies to.
	Resource OptionalList[Resource]
}

// AppliesTo returns true if the given concrete action and resource matches this policy.
// resource may be empty, in which case this policy applies as long as the action matches.
func (p *Policy) AppliesTo(action Action, resource Resource) bool {
	var matchesAction bool
	for _, rule := range p.Action {
		if WildcardMatch(rule, action) {
			matchesAction = true
			break
		}
	}

	if !matchesAction {
		return false
	}

	if resource == "" {
		return true
	}

	for _, rule := range p.Resource {
		if WildcardMatch(rule, resource) {
			return true
		}
	}

	return false
}

// EvaluatePolicy returns true if the given concrete action and resource applies to any of the given policies.
// The default action is to deny.
func EvaluatePolicy(action Action, resource Resource, policies []*Policy) *Error {
	var success bool
	for _, policy := range policies {
		// Only interested in explicit denies when at least on policy is successful
		if success && !policy.Deny {
			continue
		}

		if policy.AppliesTo(action, resource) {
			if policy.Deny {
				success = false
				break
			}

			success = true
		}
	}

	if !success {
		return &Error{
			ErrorCode: AccessDenied,
			Message:   "You do not have permission to access this resource.",
		}
	}

	return nil
}
