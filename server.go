package ls3

import (
	"github.com/google/uuid"
	"github.com/relvacode/ls3/security"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type Method func(ctx *RequestContext) *Error

type ServerOptions struct {
	Log          *zap.Logger
	Signer       Signer
	Identity     IdentityProvider
	Filesystem   BucketFilesystemProvider
	Domain       string
	GlobalPolicy []*PolicyStatement
	ClientIP     security.ClientIP
	ClientTLS    security.ClientTLS
}

func NewServer(opts *ServerOptions) *Server {
	var domainComponents []string
	if len(opts.Domain) > 0 {
		domainComponents = strings.Split(opts.Domain, ".")
	}
	return &Server{
		log:                opts.Log,
		signer:             opts.Signer,
		identities:         opts.Identity,
		filesystemProvider: opts.Filesystem,
		domain:             domainComponents,
		globalPolicy:       opts.GlobalPolicy,
		remoteIP:           opts.ClientIP,
		remoteTLS:          opts.ClientTLS,
		uidGen:             uuid.New,
	}
}

type Server struct {
	log                *zap.Logger
	signer             Signer
	identities         IdentityProvider
	filesystemProvider BucketFilesystemProvider
	domain             []string
	globalPolicy       []*PolicyStatement
	remoteIP           security.ClientIP
	remoteTLS          security.ClientTLS
	// uidGen describes the function that generates request UUID
	uidGen func() uuid.UUID
}

func (s *Server) getMethodForRequestContext(ctx *RequestContext) (Method, bool) {
	// Non-bucket methods
	if ctx.Bucket == "" {
		switch {
		case ctx.Request.Method == http.MethodGet && ctx.Request.URL.Path == "/":
			return s.ListBuckets, true
		default:
			return nil, false
		}
	}

	if ctx.Filesystem == nil {
		return nil, false
	}

	switch ctx.Request.Method {
	case http.MethodHead:
		if ctx.Request.URL.Path == "/" {
			return s.HeadBucket, true
		}

		return s.HeadObject, true

	case http.MethodGet:

		if _, ok := ctx.Request.URL.Query()["location"]; ok {
			return s.GetBucketLocation, true
		}

		if ctx.Request.URL.Path == "/" {
			switch ctx.Request.URL.Query().Get("list-type") {
			case "2":
				return s.ListObjectsV2, true
			default:
				return s.ListObjects, true
			}
		}

		return s.GetObject, true
	}

	return nil, false
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	var (
		requestId        = s.uidGen()
		clientIP         = s.remoteIP(r)
		clientTLSEnabled = s.remoteTLS(r)
	)

	rw.Header().Set("Server", "ls3")
	rw.Header().Set("x-amz-request-id", requestId.String())

	log := s.log.With(
		zap.String("request-id", requestId.String()),
		zap.String("http-method", r.Method),
		zap.String("http-uri", r.URL.RequestURI()),
		zap.String("http-user-agent", r.Header.Get("User-Agent")),
		zap.String("http-client-ip", clientIP.String()),
		zap.Bool("http-client-tls", clientTLSEnabled),
	)

	ctx := &RequestContext{
		Logger:       log,
		Request:      r,
		ID:           requestId,
		RemoteIP:     clientIP,
		Secure:       clientTLSEnabled,
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
	ctx.Bucket, ok, err = bucketFromRequest(ctx.Request, s.domain)
	if err != nil {
		ctx.SendKnownError(ErrorFrom(err))
		return
	}

	if ok {
		ctx.Filesystem, err = s.filesystemProvider.Open(ctx.Bucket)
		if err != nil {
			ctx.SendKnownError(ErrorFrom(err))
			return
		}
	}

	requestMethod, ok := s.getMethodForRequestContext(ctx)
	if !ok {
		ctx.SendKnownError(&Error{
			ErrorCode: MethodNotAllowed,
			Message:   "The specified method is not allowed against this resource.",
		})
		return
	}

	requestErr := requestMethod(ctx)
	if requestErr != nil {
		ctx.SendKnownError(requestErr)
		return
	}
}
