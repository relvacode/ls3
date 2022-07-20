package ls3

import "net/http"

func (s *Server) HeadBucket(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("x-amz-bucket-region", s.signer.Region)
	rw.WriteHeader(http.StatusOK)
}
