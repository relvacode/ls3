package ls3

import (
	"encoding/xml"
	"net/http"
)

func (s *Server) ListObjects(ctx *RequestContext) *Error {
	type ListBucketResult struct {
		XMLName        xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
		IsTruncated    bool
		Marker         string
		NextMarker     string
		Name           string
		Prefix         string
		Delimiter      string
		MaxKeys        int
		EncodingType   string
		Contents       []Contents
		CommonPrefixes []CommonPrefixes
	}

	if err := EvaluatePolicy(ListBucket, Resource(ctx.Bucket), ctx.Identity.ACL); err != nil {
		return err
	}

	maxKeys, err := listObjectsMaxKeys(ctx.Request)
	if err != nil {
		return ErrorFrom(err)
	}

	objectKeyEncoding, err := listObjectsUrlEncodingType(ctx.Request)
	if err != nil {
		return ErrorFrom(err)
	}

	var query = ctx.Request.URL.Query()
	var result = ListBucketResult{
		Name:         ctx.Bucket,
		Prefix:       query.Get("prefix"),
		MaxKeys:      maxKeys,
		Delimiter:    query.Get("delimiter"),
		Marker:       query.Get("marker"),
		EncodingType: objectKeyEncoding,
	}

	var it = NewBucketIterator(ctx.Filesystem)

	if result.Marker != "" {
		it.Seek(result.Marker)
	}

	result.Contents, err = it.PrefixScan(result.Prefix, result.Delimiter, objectKeyEncoding == "url", result.MaxKeys)
	if err != nil {
		return ErrorFrom(err)
	}

	result.CommonPrefixes = it.CommonPrefixes()
	result.IsTruncated = it.IsTruncated

	if result.IsTruncated {
		result.NextMarker = it.Continue
	}

	ctx.SendXML(http.StatusOK, &result)
	return nil
}
