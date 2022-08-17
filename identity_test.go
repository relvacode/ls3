package ls3

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestIdentity is an Identity used in most tests,
// It uses the reference example identity in the AWS documentation.
// It allows access to any method.
var TestIdentity = &Identity{
	AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	ACL: []*Policy{
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

func TestWildcardMatch(t *testing.T) {
	t.Run("any", func(t *testing.T) {
		assert.True(t, WildcardMatch("*", "test"))
	})
	t.Run("empty_rule", func(t *testing.T) {
		assert.False(t, WildcardMatch("", "test"))
	})
	t.Run("empty_object", func(t *testing.T) {
		assert.False(t, WildcardMatch("test", ""))
	})
	t.Run("exact_match", func(t *testing.T) {
		assert.True(t, WildcardMatch("test", "test"))
	})
	t.Run("prefix_match", func(t *testing.T) {
		assert.True(t, WildcardMatch("te*", "test"))
	})
	t.Run("prefix_match_short", func(t *testing.T) {
		assert.False(t, WildcardMatch("test*", "test"))
	})
	t.Run("middle_match", func(t *testing.T) {
		assert.True(t, WildcardMatch("test/*/bar", "test/foo/bar"))
	})
	t.Run("single_character_match", func(t *testing.T) {
		assert.True(t, WildcardMatch("te?t", "test"))
	})
	t.Run("single_character_match_short", func(t *testing.T) {
		assert.False(t, WildcardMatch("test?", "test"))
	})
}

func TestEvaluatePolicy(t *testing.T) {
	acl := []*Policy{
		{
			Action: []Action{
				"test:Wildcard*",
				"test:EvaluatePolicy",
			},
			Resource: []Resource{
				"a/*",
			},
		},
		{
			Action: []Action{
				"test:ExplicitDeny",
			},
			Resource: []Resource{
				"*",
			},
		},
		{
			Deny: true,
			Action: []Action{
				"test:ExplicitDeny",
			},
			Resource: []Resource{
				"this",
			},
		},
		{
			Action: []Action{
				"test:EmptyResource",
			},
			Resource: []Resource{},
		},
	}

	t.Run("allow_wildcard_action", func(t *testing.T) {
		result := EvaluatePolicy("test:WildcardAction", "a/b/c", acl)
		assert.Nil(t, result)
	})

	t.Run("allow_wildcard_resource", func(t *testing.T) {
		result := EvaluatePolicy("test:EvaluatePolicy", "a/b/c", acl)
		assert.Nil(t, result)
	})

	t.Run("allow_unmatched_denied_resource", func(t *testing.T) {
		result := EvaluatePolicy("test:ExplicitDeny", "a/b/c", acl)
		assert.Nil(t, result)
	})

	t.Run("deny_default_action", func(t *testing.T) {
		result := EvaluatePolicy("test:Undefined", "a/b/c", acl)
		assertIsError(t, result, AccessDenied)
	})

	t.Run("deny_explicit", func(t *testing.T) {
		result := EvaluatePolicy("test:ExplicitDeny", "this", acl)
		assertIsError(t, result, AccessDenied)
	})

	t.Run("deny_empty_resource", func(t *testing.T) {
		result := EvaluatePolicy("test:EmptyResource", "this", acl)
		assertIsError(t, result, AccessDenied)
	})
}
