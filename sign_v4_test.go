package ls3

import (
	"bytes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

var testSigner = SignAWSV4{
	Region:          "us-east-1",
	AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

func testSignerRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", new(bytes.Buffer))

	req.Header.Set("Host", "examplebucket.s3.amazonaws.com")
	req.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	req.Header.Set("x-amz-date", "20130524T000000Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")

	return req
}

func Test_awsV4CanonicalRequest(t *testing.T) {
	d, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	computed := awsV4CanonicalRequest(testSignerRequest(), d, []string{"host", "x-amz-content-sha256", "x-amz-date"})
	assert.Equal(t, `GET
/
max-keys=2&prefix=J
host:examplebucket.s3.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20130524T000000Z

host;x-amz-content-sha256;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, string(computed))
}

func TestSignAWSV4_Verify(t *testing.T) {
	err := testSigner.Verify(testSignerRequest())
	assert.NoError(t, err)
}
