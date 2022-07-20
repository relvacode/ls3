package ls3

import (
	"net/http"
	"strconv"
)

func (s *Server) HeadObject(rw http.ResponseWriter, r *http.Request) {
	obj, err := s.openObject(r)
	if err != nil {
		// HEAD request contains no response body
		rw.WriteHeader(errorFrom(err).StatusCode)
		return
	}

	_ = obj.Close()

	var contentLength = obj.Size

	if obj.Range != nil {
		contentLength = obj.Range.Length
		rw.Header().Set("Accept-Ranges", "bytes")
	}

	var (
		header = rw.Header()
	)
	header.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	header.Set("Content-Length", strconv.Itoa(int(contentLength)))
	header.Set("Content-Type", "binary/octet-stream")

	rw.WriteHeader(http.StatusOK)
}
