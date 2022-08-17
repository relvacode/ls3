package ls3

import "net/http"

// amzRegion is a constant pretend region for all buckets provided by this server.
const amzRegion = "us-east-1"

func (s *Server) HeadBucket(ctx *RequestContext) *Error {
	err := EvaluatePolicy(ListBucket, Resource(ctx.Bucket), ctx.Identity.ACL, ctx)
	if err != nil {
		return err
	}

	ctx.Header().Set("x-amz-bucket-region", amzRegion)
	ctx.SendPlain(http.StatusOK)
	return nil
}
