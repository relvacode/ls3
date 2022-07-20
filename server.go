package ls3

import (
	"bytes"
	"encoding/xml"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
)

var xmlContentHeader = []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

type RequestContext struct {
	*zap.Logger
	*http.Request
	ID     uuid.UUID
	Bucket string
	rw     http.ResponseWriter
}

func (ctx *RequestContext) Header() http.Header {
	return ctx.rw.Header()
}

func (ctx *RequestContext) SendPlain(statusCode int) io.Writer {
	ctx.rw.WriteHeader(statusCode)
	ctx.Info(http.StatusText(statusCode))
	return ctx.rw
}

func (ctx *RequestContext) SendXML(statusCode int, payload any) {
	ctx.rw.Header().Set("Content-Type", "application/xml")

	w := ctx.SendPlain(statusCode)
	_, _ = w.Write(xmlContentHeader)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")

	_ = enc.Encode(payload)
}

// SendKnownError replies to the caller with a concrete *Error type using the standard Amazon S3 XML error encoding.
func (ctx *RequestContext) SendKnownError(err *Error) {
	ctx.Error(err.Message, zap.String("err-code", err.Code), zap.Error(err))

	type ErrorPayload struct {
		XMLName xml.Name `xml:"Error"`
		Error
		Resource  string `xml:"Resource"`
		RequestID string `xml:"RequestId"`
	}

	ctx.SendXML(err.StatusCode, &ErrorPayload{
		Error:     *err,
		Resource:  ctx.URL.Path,
		RequestID: ctx.ID.String(),
	})
}

type Method func(ctx *RequestContext) *Error

func NewServer(log *zap.Logger, signer Signer, filesystem fs.FS, pathStyle bool) *Server {
	return &Server{
		log:       log,
		signer:    signer,
		fs:        filesystem,
		pathStyle: pathStyle,
		uidGen:    uuid.New,
	}
}

type Server struct {
	log       *zap.Logger
	signer    Signer
	fs        fs.FS
	pathStyle bool
	// uidGen describes the function that generates request UUID
	uidGen func() uuid.UUID
}

func (s *Server) method(name string, ctx *RequestContext, f Method) {
	ctx.Logger = ctx.Logger.With(zap.String("method", name))

	err := f(ctx)
	if err != nil {
		ctx.SendKnownError(err)
	}
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Server", "ls3")

	requestId := s.uidGen()

	rw.Header().Set("x-amz-request-id", requestId.String())

	log := s.log.With(
		zap.String("request-id", requestId.String()),
		zap.String("http-method", r.Method),
		zap.String("http-uri", r.URL.RequestURI()),
		zap.String("http-user-agent", r.Header.Get("User-Agent")),
		zap.String("remote-addr", r.RemoteAddr),
	)

	ctx := &RequestContext{
		Logger:  log,
		Request: r,
		ID:      requestId,
		rw:      rw,
	}

	// Verify the request
	payload, err := s.signer.Verify(r)
	if err != nil {
		ctx.SendKnownError(ErrorFrom(err))
		return
	}

	// After body has been read by signature verification,
	// replace the original request body with the raw payload
	r.Body = io.NopCloser(bytes.NewReader(payload))

	if s.pathStyle {
		pathComponents := strings.SplitN(strings.TrimLeft(r.URL.Path, "/"), "/", 2)
		var bucketName = strings.Trim(pathComponents[0], "/")

		if bucketName == "" {
			ctx.SendKnownError(&Error{
				ErrorCode: InvalidBucketName,
				Message:   "This server uses path-style addressing for bucket names.",
			})
			return
		}

		ctx.Bucket = bucketName
		r.URL.Path = "/" + strings.TrimLeft(pathComponents[1], "/")
	} else {
		// Best effort to get the bucket name from the URL host.
		// The actual bucket name doesn't really matter, but we'll try to replicate S3 as good as we can.
		host, _, _ := net.SplitHostPort(r.Host)
		if host == "" {
			host = r.Host
		}

		ctx.Bucket, _, _ = strings.Cut(host, ".")
	}

	switch r.Method {
	case http.MethodHead:
		if r.URL.Path == "/" {
			s.method("HeadBucket", ctx, s.HeadBucket)
			return
		}

		s.method("HeadObject", ctx, s.HeadObject)
		return
	case http.MethodGet:

		if _, ok := r.URL.Query()["location"]; ok {
			s.method("GetBucketLocation", ctx, s.GetBucketLocation)
			return
		}

		if r.URL.Path == "/" {
			switch r.URL.Query().Get("list-type") {
			case "2":
				s.method("ListObjectsV2", ctx, s.ListObjectsV2)
				return
			default:
				ctx.SendKnownError(&Error{
					ErrorCode: NotImplemented,
					Message:   "ListObjects is not implemented on this server.",
				})
				return
			}

		}

		s.method("GetObject", ctx, s.GetObject)
		return
	}

	ctx.SendKnownError(&Error{
		ErrorCode: MethodNotAllowed,
		Message:   "The specified method is not allowed against this resource.",
	})
}
