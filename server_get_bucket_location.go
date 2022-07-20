package ls3

import "net/http"

func (s *Server) GetBucketLocation(ctx *RequestContext) *Error {
	type LocationConstraint struct {
		LocationConstraint *string
	}

	ctx.SendXML(http.StatusOK, &LocationConstraint{})
	return nil
}
