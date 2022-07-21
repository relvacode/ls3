package ls3

import (
	"net/http"
	"strconv"
)

func (s *Server) HeadObject(ctx *RequestContext) *Error {
	obj, err := stat(ctx)
	if err != nil {
		// HEAD request contains no response body
		ctx.SendPlain(ErrorFrom(err).StatusCode)
		return nil
	}

	_ = obj.Close()

	var contentLength = obj.Size

	if obj.Range != nil {
		contentLength = obj.Range.Length
		ctx.Header().Set("Accept-Ranges", "bytes")
	}

	ctx.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	ctx.Header().Set("Content-Length", strconv.Itoa(int(contentLength)))
	ctx.Header().Set("Content-Type", "binary/octet-stream")

	ctx.SendPlain(http.StatusOK)
	return nil
}
