package ls3

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"strconv"
)

type ListBucketResultV2 struct {
	XMLName               xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string
	Prefix                string
	Delimiter             string
	MaxKeys               int
	IsTruncated           bool
	EncodingType          string
	ContinuationToken     string
	NextContinuationToken string
	StartAfter            string
	Contents              []Contents
	CommonPrefixes        []CommonPrefixes
}

// Get implements PolicyContext based on parameters set for a list bucket objects V2 request
func (r *ListBucketResultV2) Get(k string) (string, bool) {
	switch k {
	case "s3:delimiter":
		return r.Delimiter, true
	case "s3:prefix":
		return r.Prefix, true
	case "s3:max-keys":
		return strconv.Itoa(r.MaxKeys), true
	default:
		return "", false
	}
}

func (s *Server) ListObjectsV2(ctx *RequestContext) *Error {
	maxKeys, err := listObjectsMaxKeys(ctx.Request)
	if err != nil {
		return ErrorFrom(err)
	}

	objectKeyEncoding, err := listObjectsUrlEncodingType(ctx.Request)
	if err != nil {
		return ErrorFrom(err)
	}

	var query = ctx.Request.URL.Query()
	var result = ListBucketResultV2{
		Name:              ctx.Bucket,
		Prefix:            query.Get("prefix"),
		MaxKeys:           maxKeys,
		Delimiter:         query.Get("delimiter"),
		ContinuationToken: query.Get("continuation-token"),
		StartAfter:        query.Get("start-after"),
		EncodingType:      objectKeyEncoding,
	}

	if err := EvaluatePolicy(ListBucket, Resource(ctx.Bucket), ctx.Identity.ACL, JoinContext(ctx, &result)); err != nil {
		return err
	}

	var it = NewBucketIterator(ctx.Filesystem)

	// Seek bucket iterator.
	// Prefer a continuation token to the request start after
	// on the basis that the continuation token is set by >1 page.

	if result.StartAfter != "" {
		it.Seek(result.StartAfter)
	}

	if result.ContinuationToken != "" {
		continuationPathBytes, err := base64.StdEncoding.DecodeString(result.ContinuationToken)
		if err != nil {
			return &Error{
				ErrorCode: InvalidArgument,
				Message:   "You provided an invalid continuation-token.",
			}
		}

		it.Seek(string(continuationPathBytes))
	}

	result.Contents, err = it.PrefixScan(result.Prefix, result.Delimiter, objectKeyEncoding == "url", result.MaxKeys)
	if err != nil {
		return ErrorFrom(err)
	}

	result.CommonPrefixes = it.CommonPrefixes()
	result.IsTruncated = it.IsTruncated

	if result.IsTruncated {
		result.NextContinuationToken = base64.StdEncoding.EncodeToString([]byte(it.Continue))
	}

	ctx.SendXML(http.StatusOK, &result)
	return nil
}
