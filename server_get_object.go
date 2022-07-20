package ls3

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// modQueryResponseHeader injects header values into the HTTP response based on requested values of the original HTTP request.
func modQueryResponseHeader(q url.Values, hdr http.Header, queryKey, headerKey string) {
	queryValue := q.Get(queryKey)
	if queryValue == "" {
		return
	}

	hdr.Set(headerKey, queryValue)
}

func (s *Server) GetObject(rw http.ResponseWriter, r *http.Request) {
	obj, err := s.openObject(r)
	if err != nil {
		s.SendError(rw, r, err)
		return
	}

	defer obj.Close()

	var responseCode = http.StatusOK
	var contentLength = obj.Size

	if obj.Range != nil {
		// Set accepted range
		responseCode = http.StatusPartialContent
		contentLength = obj.Range.Length

		rw.Header().Set("Content-Range", obj.Range.ContentRange(obj.Size))
	}

	var (
		query  = r.URL.Query()
		header = rw.Header()
	)

	header.Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	header.Set("Content-Length", strconv.Itoa(int(contentLength)))
	header.Set("Content-Type", "binary/octet-stream")
	header.Set("Accept-Ranges", "bytes")

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html -> Overriding Response Header Values
	modQueryResponseHeader(query, header, "response-content-type", "Content-Type")
	modQueryResponseHeader(query, header, "response-content-language", "Content-Language")
	modQueryResponseHeader(query, header, "response-expires", "Expires")
	modQueryResponseHeader(query, header, "response-cache-control", "Cache-Control")
	modQueryResponseHeader(query, header, "response-content-disposition", "Content-Disposition")
	modQueryResponseHeader(query, header, "response-content-encoding", "Content-Encoding")

	// Write the response
	rw.WriteHeader(responseCode)
	_, _ = io.Copy(rw, obj)
}
