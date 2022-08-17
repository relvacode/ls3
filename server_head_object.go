package ls3

import (
	"net/http"
	"strconv"
)

func (s *Server) HeadObject(ctx *RequestContext) *Error {
	key, err := urlPathObjectKey(ctx.Request.URL.Path)
	if err != nil {
		// HEAD request that errors contains no response body
		ctx.SendPlain(ErrorFrom(err).StatusCode)
		return nil
	}

	obj, err := stat(ctx, key)
	if err != nil {
		// HEAD request that errors contains no response body
		ctx.SendPlain(ErrorFrom(err).StatusCode)
		return nil
	}

	_ = obj.Close()

	if err := EvaluatePolicy(GetObject, Resource(ctx.Bucket+"/"+key), ctx.Identity.ACL, JoinContext(ctx, obj)); err != nil {
		// HEAD request that errors contains no response body
		ctx.SendPlain(err.StatusCode)
		return nil
	}

	var header = ctx.Header()

	header.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	header.Set("ETag", strconv.Quote(obj.ETag))

	// Conditional Response
	conditional, err := checkConditionalRequest(ctx.Request.Header, obj)
	if err != nil {
		// HEAD request that errors contains no response body
		ctx.SendPlain(ErrorFrom(err).StatusCode)
		return nil
	}
	if conditional > 0 {
		ctx.SendPlain(conditional)
		return nil
	}

	var contentLength = obj.Size

	if obj.Range != nil {
		contentLength = obj.Range.Length
		header.Set("Accept-Ranges", "bytes")
	}

	header.Set("Content-Length", strconv.Itoa(int(contentLength)))
	header.Set("Content-Type", obj.ContentType)

	ctx.SendPlain(http.StatusOK)
	return nil
}
