package ls3

import (
	"bytes"
	"encoding/xml"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

var xmlContentHeader = []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

type RequestContext struct {
	*zap.Logger
	ID         uuid.UUID
	Bucket     string
	Filesystem fs.FS
	Request    *http.Request

	rw http.ResponseWriter
	// flag to indicate the context has already tried to encode the original payload.
	// Stops an endless recursion when SendXML attempts to encode a poisoned error.
	failedXmlEncode bool
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
	var b bytes.Buffer

	enc := xml.NewEncoder(&b)
	enc.Indent("", "  ")

	// Try and encode the response as XML.
	// If this fails then throw an error instead.
	err := enc.Encode(payload)
	if err != nil {
		// Detect poisoned recursion in the very unlikely case the error cannot be encoded.
		if ctx.failedXmlEncode {
			ctx.Error("XML encoding failed twice for this request context. Refusing to try again and sending a plain HTTP status code instead.")
			ctx.SendPlain(statusCode)
			return
		}

		ctx.failedXmlEncode = true
		ctx.SendKnownError(&Error{
			ErrorCode: MalformedXML,
			Message:   "The server was unable to XML encode the response.",
		})
		return
	}

	ctx.rw.Header().Set("Content-Type", "application/xml")

	w := ctx.SendPlain(statusCode)
	_, _ = w.Write(xmlContentHeader)
	_, _ = b.WriteTo(w)
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
		Resource:  ctx.Request.URL.Path,
		RequestID: ctx.ID.String(),
	})
}

type Method func(ctx *RequestContext) *Error

func NewServer(log *zap.Logger, signer Signer, buckets BucketFilesystemProvider, domain string) *Server {
	var domainComponents []string
	if len(domain) > 0 {
		domainComponents = strings.Split(domain, ".")
	}
	return &Server{
		log:     log,
		signer:  signer,
		buckets: buckets,
		domain:  domainComponents,
		uidGen:  uuid.New,
	}
}

type Server struct {
	log     *zap.Logger
	signer  Signer
	buckets BucketFilesystemProvider
	domain  []string
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
	err := s.signer.Verify(r)
	if err != nil {
		ctx.SendKnownError(ErrorFrom(err))
		return
	}

	var ok bool
	ctx.Bucket, ok, err = bucketFromRequest(r, s.domain)
	if err != nil {
		ctx.SendKnownError(ErrorFrom(err))
		return
	}

	// Non-bucket methods
	if !ok {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			s.method("ListBuckets", ctx, s.ListBuckets)
			return
		}

		ctx.SendKnownError(&Error{
			ErrorCode: MethodNotAllowed,
			Message:   "The specified method is not allowed against this resource.",
		})
	}

	ctx.Filesystem, err = s.buckets.Open(ctx.Bucket)
	if err != nil {
		ctx.SendKnownError(ErrorFrom(err))
		return
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
				s.method("ListObjects", ctx, s.ListObjects)
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
