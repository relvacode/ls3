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

	// Try to stat the object first, to allow authentication context with the object.
	obj, statErr := stat(ctx, key)
	var objCtx PolicyContextVars = NullContext{}
	if obj != nil {
		_ = obj.Close()
		objCtx = obj
	}

	if err := ctx.CheckAccess(GetObject, Resource(ctx.Bucket+"/"+key), objCtx); err != nil {
		// HEAD request that errors contains no response body
		ctx.SendPlain(err.StatusCode)
		return nil
	}

	if statErr != nil {
		// HEAD request that errors contains no response body
		ctx.SendPlain(ErrorFrom(statErr).StatusCode)
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
