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
	case "ls3:authenticated":
		return strconv.FormatBool(ctx.Identity.AccessKeyId != IdentityUnauthenticatedPublic), true
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
		statApiPolicyDenials.WithLabelValues((string)(action), (string)(resource), ctx.Identity.Name, ctx.RemoteIP.String()).Add(1)

		ctx.Logger.Error("Access to resource is denied by global policy")
		return err
	}

	// Check if identity specific policy matches request
	err = EvaluatePolicy(action, resource, ctx.Identity.Policy, policyContext)
	if err != nil {
		statApiCall.WithLabelValues((string)(action), (string)(resource), ctx.Identity.Name, ctx.RemoteIP.String()).Add(1)

		ctx.Logger.Error("Access to resource is denied by identity specific policy")
		return err
	}

	statApiCall.WithLabelValues((string)(action), (string)(resource), ctx.Identity.Name, ctx.RemoteIP.String()).Add(1)

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
