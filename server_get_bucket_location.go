package ls3

import (
	"encoding/xml"
	"net/http"
)

func (s *Server) GetBucketLocation(ctx *RequestContext) *Error {
	type LocationConstraint struct {
		XMLName            xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
		LocationConstraint string   `xml:",chardata"`
	}

	if err := ctx.CheckAccess(GetBucketLocation, Resource(ctx.Bucket), NullContext{}); err != nil {
		return err
	}

	ctx.SendXML(http.StatusOK, &LocationConstraint{})
	return nil
}
