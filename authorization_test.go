package ls3

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestParseCredential(t *testing.T) {
	var expect = "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"

	credential, err := ParseCredential(expect)
	assert.NoError(t, err)

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", credential.AccessKeyID)
	assert.True(t, time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC).Equal(credential.Date))
	assert.Equal(t, "us-east-1", credential.Region)
	assert.Equal(t, "s3", credential.Service)
	assert.Equal(t, "aws4_request", credential.Type)

	t.Run("AppendFormat", func(t *testing.T) {
		b := credential.AppendFormat(nil)
		assert.Equal(t, expect, string(b))
	})
}

func TestParseAuthorization(t *testing.T) {
	var expect = `AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41`

	auth, err := ParseAuthorizationHeader(expect)
	assert.NoError(t, err)

	assert.Equal(t, 4, len(auth.SignedHeaders))

	t.Run("AppendFormat", func(t *testing.T) {
		b := auth.AppendFormat(nil)
		assert.Equal(t, expect, string(b))
	})
}
