package ls3

import (
	"bytes"
	"context"
	"encoding/xml"
	"github.com/google/uuid"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
)

type contextKeyType int

const (
	contextRequestIdKey contextKeyType = iota + 1
	contextRequestBucketName
)

var xmlContentHeader = []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

func BucketFromContext(ctx context.Context) string {
	v := ctx.Value(contextRequestBucketName)
	if v == nil {
		return ""
	}

	return v.(string)
}

func NewServer(signer Signer, filesystem fs.FS, pathStyle bool) *Server {
	return &Server{
		signer:    signer,
		fs:        filesystem,
		pathStyle: pathStyle,
		uidGen:    uuid.New,
	}
}

type Server struct {
	signer    Signer
	fs        fs.FS
	pathStyle bool
	// uidGen describes the function that generates request UUID
	uidGen func() uuid.UUID
}

func (s *Server) SendXML(rw http.ResponseWriter, statusCode int, payload any) {
	rw.Header().Set("Content-Type", "application/xml")
	rw.WriteHeader(statusCode)

	_, _ = rw.Write(xmlContentHeader)

	w := io.MultiWriter(rw, os.Stderr)

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")

	_ = enc.Encode(payload)
}

// SendKnownError replies to the caller with a concrete *Error type using the standard Amazon S3 XML error encoding.
func (s *Server) SendKnownError(rw http.ResponseWriter, r *http.Request, err *Error) {
	type ErrorPayload struct {
		XMLName xml.Name `xml:"Error"`
		Error
		Resource  string `xml:"Resource"`
		RequestID string `xml:"RequestId"`
	}

	var uid uuid.UUID

	id := r.Context().Value(contextRequestIdKey)
	if id != nil {
		uid, _ = id.(uuid.UUID)
	}

	s.SendXML(rw, err.StatusCode, &ErrorPayload{
		Error:     *err,
		Resource:  r.URL.Path,
		RequestID: uid.String(),
	})
}

// SendError replies to the caller with an opaque error type using the standard Amazon S3 XML error encoding.
// If err is not an *Error then a generic InvalidRequest is sent with the error message as the contents.
func (s *Server) SendError(rw http.ResponseWriter, r *http.Request, err error) {
	s.SendKnownError(rw, r, errorFrom(err))
}

// WithAuthorizedContext calls a http.HandlerFunc only after a request has been authorized and verified.
func (s *Server) WithAuthorizedContext(rw http.ResponseWriter, r *http.Request, handler http.HandlerFunc) {

	handler(rw, r)
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Server", "ls3")

	id := s.uidGen()
	r = r.WithContext(context.WithValue(r.Context(), contextRequestIdKey, id))

	rw.Header().Set("x-amz-request-id", id.String())

	log.Println(r.Method, r.Host, r.URL)
	log.Println(r.Header)

	// Verify the request
	payload, err := s.signer.Verify(r)
	if err != nil {
		s.SendError(rw, r, err)
		return
	}

	// After body has been read by signature verification,
	// replace the original request body with the raw payload
	r.Body = io.NopCloser(bytes.NewReader(payload))

	if s.pathStyle {
		pathComponents := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		var bucketName = strings.Trim(pathComponents[0], "/")

		if bucketName == "" {
			s.SendKnownError(rw, r, &Error{
				ErrorCode: InvalidBucketName,
				Message:   "This server uses path-style addressing for bucket names.",
			})
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), contextRequestBucketName, bucketName))
		r.URL.Path = pathComponents[1]
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}

	switch r.Method {
	case http.MethodHead:
		if r.URL.Path == "/" {
			s.HeadBucket(rw, r)
			return
		}

		s.HeadObject(rw, r)
		return
	case http.MethodGet:

		if _, ok := r.URL.Query()["location"]; ok {
			s.GetBucketLocation(rw, r)
			return
		}

		if r.URL.Path == "/" {
			switch r.URL.Query().Get("list-type") {
			case "2":
				s.ListObjectsV2(rw, r)
				return
			default:
				s.SendKnownError(rw, r, &Error{
					ErrorCode: NotImplemented,
					Message:   "ListObjects is not implemented on this server.",
				})
				return
			}

		}

		s.GetObject(rw, r)
		return
	}

	s.SendKnownError(rw, r, &Error{
		ErrorCode: MethodNotAllowed,
		Message:   "The specified method is not allowed against this resource.",
	})
}
