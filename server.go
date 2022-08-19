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
	"strconv"
	"strings"
)

var xmlContentHeader = []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

type RequestContext struct {
	*zap.Logger
	ID         uuid.UUID
	Bucket     string
	Filesystem fs.FS
	Request    *http.Request
	Identity   *Identity

	// The client IP address
	RemoteIP net.IP
	// Is this connection secure
	Secure bool

	globalPolicy []*PolicyStatement

	rw http.ResponseWriter
	// flag to indicate the context has already tried to encode the original payload.
	// Stops an endless recursion when SendXML attempts to encode a poisoned error.
	failedXmlEncode bool
}

// Get implements PolicyContextVars for this request.
func (ctx *RequestContext) Get(k string) (string, bool) {
	switch k {
	case "aws:SourceIp":
		return ctx.RemoteIP.String(), true
	case "aws:SecureTransport":
		return strconv.FormatBool(ctx.Secure), true
	case "aws:username":
		return ctx.Identity.Name, true
	default:
		return "", false
	}
}

// CheckAccess verifies that the current identity has the appropriate permissions to execute the given access for the given resource.
// vars are additional PolicyContextVars that will be used in the conditional policy evaluation.
// CheckAccess will first verify that the request meets the global policy,
// if that succeeds it will then check the identity specific PolicyStatement.
func (ctx *RequestContext) CheckAccess(action Action, resource Resource, vars PolicyContextVars) *Error {
	ctx.Logger = ctx.Logger.With(
		zap.String("action", string(action)),
		zap.String("resource", string(resource)),
	)

	policyContext := JoinContext(ctx, vars)

	// Check global policy first
	err := EvaluatePolicy(action, resource, ctx.globalPolicy, policyContext)
	if err != nil {
		ctx.Logger.Error("Access to resource is denied by global policy")
		return err
	}

	// Check if identity specific policy matches request
	err = EvaluatePolicy(action, resource, ctx.Identity.Policy, policyContext)
	if err != nil {
		ctx.Logger.Error("Access to resource is denied by identity specific policy")
		return err
	}

	return nil
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

func NewServer(log *zap.Logger, signer Signer, identities IdentityProvider, buckets BucketFilesystemProvider, domain string, globalPolicy []*PolicyStatement) *Server {
	var domainComponents []string
	if len(domain) > 0 {
		domainComponents = strings.Split(domain, ".")
	}
	return &Server{
		log:          log,
		signer:       signer,
		identities:   identities,
		buckets:      buckets,
		domain:       domainComponents,
		globalPolicy: globalPolicy,
		uidGen:       uuid.New,
	}
}

type Server struct {
	log          *zap.Logger
	signer       Signer
	identities   IdentityProvider
	buckets      BucketFilesystemProvider
	domain       []string
	globalPolicy []*PolicyStatement
	// uidGen describes the function that generates request UUID
	uidGen func() uuid.UUID
}

func (s *Server) method(method string, ctx *RequestContext, f Method) {
	ctx.Logger = ctx.Logger.With(zap.String("method", method))

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

	var remoteIP net.IP
	if remoteIpStr, _, splitHostErr := net.SplitHostPort(r.RemoteAddr); splitHostErr == nil {
		remoteIP = net.ParseIP(remoteIpStr)
	}

	ctx := &RequestContext{
		Logger:  log,
		Request: r,
		ID:      requestId,
		// TODO configure RemoteIP through X-Forwarded-Ip
		RemoteIP: remoteIP,
		// TODO configure secure through X-Forwarded-Proto
		Secure:       r.TLS != nil,
		globalPolicy: s.globalPolicy,
		rw:           rw,
	}

	var err error

	// Verify the request
	ctx.Identity, err = s.signer.Verify(r, s.identities)
	if err != nil {
		ctx.SendKnownError(ErrorFrom(err))
		return
	}

	// Identity not present in the request.
	// Ask the identity provider to provide for IdentityUnauthenticatedPublic
	if ctx.Identity == nil {
		ctx.Identity, err = s.identities.Get(IdentityUnauthenticatedPublic)
		if err != nil {
			ctx.SendKnownError(ErrorFrom(err))
			return
		}
	}

	ctx.Logger = ctx.Logger.With(
		zap.String("identity", ctx.Identity.Name),
	)

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
