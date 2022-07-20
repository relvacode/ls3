package ls3

import "net/http"

func (s *Server) HeadBucket(ctx *RequestContext) *Error {
	ctx.Header().Set("x-amz-bucket-region", s.signer.Region)
	ctx.SendPlain(http.StatusOK)
	return nil
}
