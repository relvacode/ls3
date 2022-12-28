package ls3

import "net/http"

// amzRegion is a constant pretend region for all filesystemProvider provided by this server.
const amzRegion = "us-east-1"

func (s *Server) HeadBucket(ctx *RequestContext) *Error {
	err := ctx.CheckAccess(ListBucket, Resource(ctx.Bucket), NullContext{})
	if err != nil {
		// HEAD returns no body
		ctx.SendPlain(err.StatusCode)
		return nil
	}

	ctx.Header().Set("x-amz-bucket-region", amzRegion)
	ctx.SendPlain(http.StatusOK)
	return nil
}
