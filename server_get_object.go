package ls3

import (
	"github.com/relvacode/ls3/exception"
	"github.com/relvacode/ls3/idp"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// modQueryResponseHeader injects header values into the HTTP response based on requested values of the original HTTP request.
func modQueryResponseHeader(q url.Values, hdr http.Header, queryKey, headerKey string) {
	queryValue := q.Get(queryKey)
	if queryValue == "" {
		return
	}

	hdr.Set(headerKey, queryValue)
}

func (s *Server) GetObject(ctx *RequestContext) *exception.Error {
	key, err := urlPathObjectKey(ctx.Request.URL.Path)
	if err != nil {
		return exception.ErrorFrom(err)
	}

	// Try to stat the object first, to allow authentication context with the object.
	obj, statErr := stat(ctx, key)
	var objCtx idp.PolicyContextVars = idp.NullContext{}
	if obj != nil {
		defer obj.Close()
		objCtx = obj
	}

	if err := ctx.CheckAccess(idp.GetObject, idp.Resource(ctx.Bucket+"/"+key), objCtx); err != nil {
		return err
	}

	if statErr != nil {
		// The request must have ListBucket access to see the real error behind accessing the object
		if err := ctx.CheckAccess(idp.ListBucket, idp.Resource(ctx.Bucket), objCtx); err != nil {
			return err
		}

		return exception.ErrorFrom(statErr)
	}

	var (
		query  = ctx.Request.URL.Query()
		header = ctx.Header()
	)

	header.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	header.Set("ETag", strconv.Quote(obj.ETag))

	// Conditional Response
	conditional, err := checkConditionalRequest(ctx.Request.Header, obj)
	if err != nil {
		return exception.ErrorFrom(err)
	}
	if conditional > 0 {
		ctx.SendPlain(conditional)
		return nil
	}

	var responseCode = http.StatusOK
	var contentLength = obj.Size

	if obj.Range != nil {
		// Set accepted range
		responseCode = http.StatusPartialContent
		contentLength = obj.Range.Length
		header.Set("Content-Range", obj.Range.ContentRange(obj.Size))
	}

	header.Set("Content-Length", strconv.Itoa(int(contentLength)))
	header.Set("Content-Type", obj.ContentType)
	header.Set("Accept-Ranges", "bytes")

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html -> Overriding Response Header Values
	modQueryResponseHeader(query, header, "response-content-type", "Content-Type")
	modQueryResponseHeader(query, header, "response-content-language", "Content-Language")
	modQueryResponseHeader(query, header, "response-expires", "Expires")
	modQueryResponseHeader(query, header, "response-cache-control", "Cache-Control")
	modQueryResponseHeader(query, header, "response-content-disposition", "Content-Disposition")
	modQueryResponseHeader(query, header, "response-content-encoding", "Content-Encoding")

	// Write the response
	bytesSent, _ := io.Copy(ctx.SendPlain(responseCode), obj)

	// Update statistics
	statBytesTransferredOut.WithLabelValues(ctx.Bucket, key, ctx.Identity.Name, ctx.RemoteIP.String()).Add(float64(bytesSent))

	return nil
}
