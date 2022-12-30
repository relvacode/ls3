package idp

import (
	"bytes"
	"encoding/json"
	"github.com/relvacode/ls3/exception"
	"net"
	"strings"
)

type Action string

const (
	GetObject         Action = "s3:GetObject"
	ListAllMyBuckets  Action = "s3:ListAllMyBuckets"
	ListBucket        Action = "s3:ListBucket"
	GetBucketLocation Action = "s3:GetBucketLocation"
)

type Resource string

type ConditionOperator string

const (
	StringEquals              ConditionOperator = "StringEquals"
	StringNotEquals           ConditionOperator = "StringNotEquals"
	StringEqualsIgnoreCase    ConditionOperator = "StringEqualsIgnoreCase"
	StringNotEqualsIgnoreCase ConditionOperator = "StringNotEqualsIgnoreCase"
	StringLike                ConditionOperator = "StringLike"
	StringNotLike             ConditionOperator = "StringNotLike"
	IpAddress                 ConditionOperator = "IpAddress"
	NotIpAddress              ConditionOperator = "NotIpAddress"
	Bool                      ConditionOperator = "Bool"
)

func WildcardMatch[T ~string](rule, obj T) bool {
	if len(rule) == 0 || len(obj) == 0 {
		return false
	}

	// Wildcard any
	if rule == "*" {
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

type PolicyConditions map[ConditionOperator]map[string]OptionalList[string]

type PolicyContextVars interface {
	Get(k string) (string, bool)
}

// MapContext implements PolicyContextVars for a map.
type MapContext map[string]string

func (ctx MapContext) Get(k string) (string, bool) {
	v, ok := ctx[k]
	return v, ok
}

// NullContext implements PolicyContextVars but never returns a value
type NullContext struct{}

func (NullContext) Get(_ string) (string, bool) {
	return "", false
}

// joinContext implements PolicyContextVars by joining the current context with a parent.
type joinContext struct {
	parent PolicyContextVars
	PolicyContextVars
}

func (j *joinContext) Get(k string) (string, bool) {
	v, ok := j.PolicyContextVars.Get(k)
	if !ok {
		return j.parent.Get(k)
	}

	return v, true
}

func JoinContext(parent PolicyContextVars, this PolicyContextVars) PolicyContextVars {
	return &joinContext{
		parent:            parent,
		PolicyContextVars: this,
	}
}

// ipOrCidr attempts to parse the value as an IP address or CIDR range.
// If value is an IP address then implicitly the returned range is {IP}/32.
// Returns nil if v is neither an IP or a CIDR.
func ipOrCidr(v string) *net.IPNet {
	_, cidr, _ := net.ParseCIDR(v)
	if cidr != nil {
		return cidr
	}

	ip := net.ParseIP(v)
	if ip.IsUnspecified() {
		return nil
	}

	var mask net.IPMask
	if len(ip) == 4 { // ipv4
		mask = net.CIDRMask(32, 32)
	} else {
		mask = net.CIDRMask(128, 128)
	}

	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func evaluateOperatorKey(operator ConditionOperator, key string, values []string, context PolicyContextVars) bool {
	expect, ok := context.Get(key)
	if !ok {
		// No such key within context. Impossible to satisfy condition
		return false
	}

	switch operator {
	case StringEquals:
		// True if any value equals expect
		for _, v := range values {
			if v == expect {
				return true
			}
		}
		return false
	case StringNotEquals:
		// False if any value equals expect
		for _, v := range values {
			if v == expect {
				return false
			}
		}
		return true
	case StringEqualsIgnoreCase:
		// True if any value equals expect
		expect = strings.ToLower(expect)
		for _, v := range values {
			if strings.ToLower(v) == expect {
				return true
			}
		}
		return false
	case StringNotEqualsIgnoreCase:
		// True if any value equals expect
		expect = strings.ToLower(expect)
		for _, v := range values {
			if strings.ToLower(v) == expect {
				return false
			}
		}
		return true
	case StringLike:
		// True if any wildcard matches
		for _, v := range values {
			if WildcardMatch(v, expect) {
				return true
			}
		}
		return false
	case StringNotLike:
		// False if any wildcard matches
		for _, v := range values {
			if WildcardMatch(v, expect) {
				return false
			}
		}
		return true
	case IpAddress:
		expectIp := net.ParseIP(expect)
		if expectIp.IsUnspecified() {
			// An invalid IP is always false
			return false
		}

		// Values can be one an IP or CIDR
		for _, v := range values {
			cidr := ipOrCidr(v)
			if cidr == nil {
				// Cannot parse invalid CIDR
				return false
			}

			if cidr.Contains(expectIp) {
				return true
			}
		}
		return false
	case NotIpAddress:
		expectIp := net.ParseIP(expect)
		if expectIp.IsUnspecified() {
			// An invalid IP is always false
			return false
		}

		// Values can be one an IP or CIDR
		for _, v := range values {
			cidr := ipOrCidr(v)
			if cidr == nil {
				// Cannot parse invalid CIDR
				return false
			}

			if cidr.Contains(expectIp) {
				return false
			}
		}
		return true
	case Bool:
		var expectBool bool
		switch expect {
		case "true":
			expectBool = true
		case "false":
		default:
			// Expect is not a valid boolean
			return false
		}

		for _, v := range values {
			switch v {
			case "true":
				return expectBool == true
			case "false":
				return expectBool == false
			default:
				return false
			}
		}
		return false
	default:
		// Unknown operator
		return false
	}
}

func evaluateOperator(operator ConditionOperator, conditions map[string]OptionalList[string], context PolicyContextVars) bool {
	for key, values := range conditions {
		if !evaluateOperatorKey(operator, key, values, context) {
			return false
		}
	}

	return true
}

func MatchesConditions(conditions PolicyConditions, context PolicyContextVars) bool {
	if len(conditions) == 0 {
		// Unconditional request
		return true
	}

	for operator, values := range conditions {
		if !evaluateOperator(operator, values, context) {
			return false
		}
	}

	return true
}

type PolicyStatement struct {
	// Deny marks this policy as an explicit deny.
	Deny bool
	// Action one or more actions that this policy applies to.
	Action OptionalList[Action]
	// Resource is one or more resources that this policy applies to.
	Resource OptionalList[Resource]
	// Condition sets conditions on when this policy applies.
	Condition PolicyConditions `json:",omitempty"`
}

// AppliesTo returns true if the given concrete action and resource matches this policy.
// resource may be empty, in which case this policy applies as long as the action matches.
func (p *PolicyStatement) AppliesTo(action Action, resource Resource, context PolicyContextVars) bool {
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

	if resource != "" {
		var matchesResource bool

		for _, rule := range p.Resource {
			if WildcardMatch(rule, resource) {
				matchesResource = true
				break
			}
		}

		if !matchesResource {
			return false
		}
	}

	return MatchesConditions(p.Condition, context)
}

// EvaluatePolicy returns true if the given concrete action and resource applies to any of the given policies.
// The default action is to deny.
func EvaluatePolicy(action Action, resource Resource, policies []*PolicyStatement, context PolicyContextVars) *exception.Error {
	var success bool
	for _, policy := range policies {
		// Only interested in explicit denies when at least on policy is successful
		if success && !policy.Deny {
			continue
		}

		if policy.AppliesTo(action, resource, context) {
			if policy.Deny {
				success = false
				break
			}

			success = true
		}
	}

	if !success {
		return &exception.Error{
			ErrorCode: exception.AccessDenied,
			Message:   "You do not have permission to access this resource.",
		}
	}

	return nil
}
