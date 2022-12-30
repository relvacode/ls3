package idp

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

type MockProvider struct{}

func (MockProvider) Get(_ string) (*Identity, error) {
	return TestIdentity, nil
}
