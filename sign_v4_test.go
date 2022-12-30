package ls3

import (
	"bytes"
	"errors"
	"github.com/relvacode/ls3/exception"
	"github.com/relvacode/ls3/idp"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

func testHeaderSignRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?prefix=J&max-keys=2", new(bytes.Buffer))

	req.Header.Set("Host", "examplebucket.s3.amazonaws.com")
	req.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")

	return req
}

func Test_awsV4CanonicalRequest(t *testing.T) {
	computed := awsV4CanonicalRequest(testHeaderSignRequest(), []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), []string{"host", "x-amz-content-sha256", "x-amz-date"})
	assert.Equal(t, `GET
/
max-keys=2&prefix=J
host:examplebucket.s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20130524T000000Z

host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, string(computed))
}

func TestSignAWSV4_VerifyHeaders(t *testing.T) {
	_, err := SignAWSV4{}.VerifyHeaders(testHeaderSignRequest(), idp.MockProvider{})
	assert.NoError(t, err)
}

func TestSignAWSV4_VerifyHeaders_UnsignedPayload(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", new(bytes.Buffer))

	req.Header.Set("Host", "examplebucket.s3.amazonaws.com")
	req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=b1a076428fa68c2c42202ee5a5718b8207f725e451e2157d6b1c393e01fc2e68")

	_, err := SignAWSV4{}.Verify(req, idp.MockProvider{})
	assert.NoError(t, err)
}

func TestSignAWSV4_VerifyQuery(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", new(bytes.Buffer))
		req.Header.Set("Host", "examplebucket.s3.amazonaws.com")

		sign := SignAWSV4{}
		sign.timeNow = func() time.Time {
			return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
		}

		_, err := sign.VerifyQuery(req, idp.MockProvider{})
		assert.NoError(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", new(bytes.Buffer))
		req.Header.Set("Host", "examplebucket.s3.amazonaws.com")

		sign := SignAWSV4{}
		sign.timeNow = func() time.Time {
			return time.Date(2013, 6, 24, 0, 0, 0, 0, time.UTC)
		}

		_, err := sign.VerifyQuery(req, idp.MockProvider{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, &exception.Error{ErrorCode: exception.ExpiredToken}))
	})
}
