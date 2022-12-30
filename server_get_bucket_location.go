package ls3

import (
	"encoding/xml"
	"github.com/relvacode/ls3/exception"
	"github.com/relvacode/ls3/idp"
	"net/http"
)

func (s *Server) GetBucketLocation(ctx *RequestContext) *exception.Error {
	type LocationConstraint struct {
		XMLName            xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
		LocationConstraint string   `xml:",chardata"`
	}

	if err := ctx.CheckAccess(idp.GetBucketLocation, idp.Resource(ctx.Bucket), idp.NullContext{}); err != nil {
		return err
	}

	ctx.SendXML(http.StatusOK, &LocationConstraint{})
	return nil
}
