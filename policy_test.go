package ls3

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func Test_ipOrCidr(t *testing.T) {
	t.Run("ip", func(t *testing.T) {
		cidr := ipOrCidr("127.0.0.1")
		t.Log(cidr)
		assert.True(t, cidr.Contains(net.IPv4(127, 0, 0, 1)))
		assert.False(t, cidr.Contains(net.IPv4(127, 0, 0, 2)))
	})
	t.Run("cidr", func(t *testing.T) {
		cidr := ipOrCidr("192.168.0.0/24")
		t.Log(cidr)
		assert.True(t, cidr.Contains(net.IPv4(192, 168, 0, 128)))
	})
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
	acl := []*PolicyStatement{
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
		result := EvaluatePolicy("test:WildcardAction", "a/b/c", acl, MapContext{})
		assert.Nil(t, result)
	})

	t.Run("allow_wildcard_resource", func(t *testing.T) {
		result := EvaluatePolicy("test:EvaluatePolicy", "a/b/c", acl, MapContext{})
		assert.Nil(t, result)
	})

	t.Run("allow_unmatched_denied_resource", func(t *testing.T) {
		result := EvaluatePolicy("test:ExplicitDeny", "a/b/c", acl, MapContext{})
		assert.Nil(t, result)
	})

	t.Run("deny_default_action", func(t *testing.T) {
		result := EvaluatePolicy("test:Undefined", "a/b/c", acl, MapContext{})
		assertIsError(t, result, AccessDenied)
	})

	t.Run("deny_explicit", func(t *testing.T) {
		result := EvaluatePolicy("test:ExplicitDeny", "this", acl, MapContext{})
		assertIsError(t, result, AccessDenied)
	})

	t.Run("deny_empty_resource", func(t *testing.T) {
		result := EvaluatePolicy("test:EmptyResource", "this", acl, MapContext{})
		assertIsError(t, result, AccessDenied)
	})
}

func TestMatchesConditions(t *testing.T) {
	t.Run("unconditional", func(t *testing.T) {
		assert.True(t, MatchesConditions(PolicyConditions{}, MapContext{}))
	})
	t.Run("matches_StringEquals_true", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				StringEquals: map[string]OptionalList[string]{
					"key": []string{"Yes"},
				},
			},
			MapContext{
				"key": "Yes",
			},
		))
	})
	t.Run("matches_StringEquals_false", func(t *testing.T) {
		assert.False(t, MatchesConditions(
			PolicyConditions{
				StringEquals: map[string]OptionalList[string]{
					"key": []string{"Yes"},
				},
			},
			MapContext{
				"key": "No",
			},
		))
	})
	t.Run("matches_StringNotEquals_true", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				StringNotEquals: map[string]OptionalList[string]{
					"key": []string{"No"},
				},
			},
			MapContext{
				"key": "Yes",
			},
		))
	})
	t.Run("matches_StringNotEquals_false", func(t *testing.T) {
		assert.False(t, MatchesConditions(
			PolicyConditions{
				StringNotEquals: map[string]OptionalList[string]{
					"key": []string{"Yes"},
				},
			},
			MapContext{
				"key": "Yes",
			},
		))
	})
	t.Run("matches_StringEqualsIgnoreCase_true", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				StringEqualsIgnoreCase: map[string]OptionalList[string]{
					"key": []string{"yEs"},
				},
			},
			MapContext{
				"key": "Yes",
			},
		))
	})
	t.Run("matches_StringLike_true", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				StringLike: map[string]OptionalList[string]{
					"key": []string{"*/bar"},
				},
			},
			MapContext{
				"key": "foo/bar",
			},
		))
	})
	t.Run("matches_StringNotLike_false", func(t *testing.T) {
		assert.False(t, MatchesConditions(
			PolicyConditions{
				StringNotLike: map[string]OptionalList[string]{
					"key": []string{"*/bar"},
				},
			},
			MapContext{
				"key": "foo/bar",
			},
		))
	})
	t.Run("matches_IpAddress_ip4", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				IpAddress: map[string]OptionalList[string]{
					"key": []string{"127.0.0.1"},
				},
			},
			MapContext{
				"key": "127.0.0.1",
			},
		))
	})
	t.Run("matches_IpAddress_ip4_cidr32", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				IpAddress: map[string]OptionalList[string]{
					"key": []string{"127.0.0.1/32"},
				},
			},
			MapContext{
				"key": "127.0.0.1",
			},
		))
	})
	t.Run("matches_IpAddress_ip4_cidr24", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				IpAddress: map[string]OptionalList[string]{
					"key": []string{
						"127.0.0.1/32",
						"192.168.0.1/24",
					},
				},
			},
			MapContext{
				"key": "192.168.0.128",
			},
		))
	})
	t.Run("matches_NotIpAddress_ip4_cidr", func(t *testing.T) {
		assert.False(t, MatchesConditions(
			PolicyConditions{
				NotIpAddress: map[string]OptionalList[string]{
					"key": []string{"127.0.0.1/32"},
				},
			},
			MapContext{
				"key": "127.0.0.1",
			},
		))
	})
	t.Run("matches_Bool_true", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				Bool: map[string]OptionalList[string]{
					"key": []string{"true"},
				},
			},
			MapContext{
				"key": "true",
			},
		))
	})
	t.Run("matches_Bool_false", func(t *testing.T) {
		assert.True(t, MatchesConditions(
			PolicyConditions{
				Bool: map[string]OptionalList[string]{
					"key": []string{"false"},
				},
			},
			MapContext{
				"key": "false",
			},
		))
	})
	t.Run("matches_Bool_notbool", func(t *testing.T) {
		assert.False(t, MatchesConditions(
			PolicyConditions{
				Bool: map[string]OptionalList[string]{
					"key": []string{"false"},
				},
			},
			MapContext{
				"key": "123",
			},
		))
	})
}
