package ls3

import "net/http"

func (s *Server) GetBucketLocation(rw http.ResponseWriter, r *http.Request) {
	type LocationConstraint struct {
		LocationConstraint *string
	}

	s.SendXML(rw, http.StatusOK, &LocationConstraint{})
}
