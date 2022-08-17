package ls3

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
