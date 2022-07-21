package ls3

import "fmt"

type ErrorCode struct {
	Code       string `xml:"Code"`
	StatusCode int    `xml:"-"`
}

var (
	AccessDenied          = ErrorCode{Code: "AccessDenied", StatusCode: 403}
	InvalidAccessKeyId    = ErrorCode{Code: "InvalidAccessKeyId", StatusCode: 403}
	SignatureDoesNotMatch = ErrorCode{Code: "SignatureDoesNotMatch", StatusCode: 403}
	MethodNotAllowed      = ErrorCode{Code: "MethodNotAllowed", StatusCode: 405}
	InvalidRequest        = ErrorCode{Code: "InvalidRequest", StatusCode: 400}
	ExpiredToken          = ErrorCode{Code: "ExpiredToken", StatusCode: 400}
	InvalidArgument       = ErrorCode{Code: "InvalidArgument", StatusCode: 400}
	BadDigest             = ErrorCode{Code: "BadDigest", StatusCode: 400}
	NoSuchKey             = ErrorCode{Code: "NoSuchKey", StatusCode: 404}
	MissingSecurityHeader = ErrorCode{Code: "MissingSecurityHeader", StatusCode: 400}
	InvalidToken          = ErrorCode{Code: "InvalidToken", StatusCode: 400}
	InvalidObjectState    = ErrorCode{Code: "InvalidObjectState", StatusCode: 403}
	InvalidRange          = ErrorCode{Code: "InvalidRange", StatusCode: 416}
	InvalidBucketName     = ErrorCode{Code: "InvalidBucketName", StatusCode: 400}
	NotImplemented        = ErrorCode{Code: "NotImplemented", StatusCode: 501}
	NoSuchBucket          = ErrorCode{Code: "NoSuchBucket", StatusCode: 404}
	InvalidBucketState    = ErrorCode{Code: "InvalidBucketState", StatusCode: 409}
	InternalError         = ErrorCode{Code: "InternalError", StatusCode: 500}
)

type Error struct {
	ErrorCode
	Message string `xml:"Message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%d] %s: %s", e.StatusCode, e.Code, e.Message)
}

func ErrorFrom(err error) *Error {
	switch e := err.(type) {
	case *Error:
		return e
	default:
		return &Error{
			ErrorCode: InvalidRequest,
			Message:   err.Error(),
		}
	}
}
