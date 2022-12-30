package ls3

import (
	"github.com/relvacode/ls3/exception"
	"github.com/relvacode/ls3/idp"
	"net/http"
)

// amzRegion is a constant pretend region for all filesystemProvider provided by this server.
const amzRegion = "us-east-1"

func (s *Server) HeadBucket(ctx *RequestContext) *exception.Error {
	err := ctx.CheckAccess(idp.ListBucket, idp.Resource(ctx.Bucket), idp.NullContext{})
	if err != nil {
		// HEAD returns no body
		ctx.SendPlain(err.StatusCode)
		return nil
	}

	ctx.Header().Set("x-amz-bucket-region", amzRegion)
	ctx.SendPlain(http.StatusOK)
	return nil
}
