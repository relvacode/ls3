package ls3

import (
	"encoding/xml"
	"github.com/relvacode/ls3/exception"
	"github.com/relvacode/ls3/idp"
	"net/http"
	"strconv"
)

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

// Get implements PolicyContextVars based on parameters set for a list bucket request
func (r *ListBucketResult) Get(k string) (string, bool) {
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

func (s *Server) ListObjects(ctx *RequestContext) *exception.Error {
	maxKeys, err := listObjectsMaxKeys(ctx.Request)
	if err != nil {
		return exception.ErrorFrom(err)
	}

	objectKeyEncoding, err := listObjectsUrlEncodingType(ctx.Request)
	if err != nil {
		return exception.ErrorFrom(err)
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

	if err := ctx.CheckAccess(idp.ListBucket, idp.Resource(ctx.Bucket), &result); err != nil {
		return err
	}

	var it = NewBucketIterator(ctx.Filesystem)

	if result.Marker != "" {
		it.Seek(result.Marker)
	}

	result.Contents, err = it.PrefixScan(result.Prefix, result.Delimiter, objectKeyEncoding == "url", result.MaxKeys)
	if err != nil {
		return exception.ErrorFrom(err)
	}

	result.CommonPrefixes = it.CommonPrefixes()
	result.IsTruncated = it.IsTruncated

	if result.IsTruncated {
		result.NextMarker = it.Continue
	}

	ctx.SendXML(http.StatusOK, &result)
	return nil
}
