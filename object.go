package ls3

import (
	"errors"
	"github.com/gotd/contrib/http_range"
	"github.com/h2non/filetype"
	"io"
	"io/fs"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Object struct {
	io.ReadCloser

	Size         int64
	Range        *http_range.Range
	LastModified time.Time
	// ContentType contains the MIME type of the object data.
	// It is the best guess based on the filetype library.
	// This is always set, if unknown the MIME type becomes application/octet-stream
	ContentType string
	// ETag represents the ETag field of the Object.
	// It is always empty.
	ETag string
}

// Get implements PolicyContextVars for this Object
func (obj *Object) Get(k string) (string, bool) {
	switch k {
	case "ls3:ObjectSize":
		return strconv.FormatInt(obj.Size, 10), true
	case "ls3:ObjectContentType":
		return obj.ContentType, true
	case "ls3:ObjectLastModified":
		return obj.LastModified.Format(time.RFC3339), true
	default:
		return "", false
	}
}

func urlPathObjectKey(urlPath string) (string, error) {
	if len(urlPath) < 1 {
		return "", &Error{
			ErrorCode: InvalidArgument,
			Message:   "Object key must be at least 1 character",
		}
	}

	// Clean the path
	urlPath = path.Clean(urlPath)
	urlPath = strings.TrimLeft(urlPath, "/")

	return urlPath, nil
}

func unwrapFsError(err error) *Error {
	for unwrap := err; unwrap != nil; unwrap = errors.Unwrap(unwrap) {
		switch {
		case os.IsNotExist(unwrap):
			return &Error{
				ErrorCode: NoSuchKey,
				Message:   "The specified object key does not exist.",
			}
		case os.IsPermission(unwrap):
			return &Error{
				ErrorCode: AccessDenied,
				Message:   "You do not have permission to access this object.",
			}
		}
	}

	return &Error{
		ErrorCode: InvalidObjectState,
		Message:   "An undefined permanent error occurred accessing this object.",
	}
}

// checkConditionalRequest checks conditional parameters present in HTTP headers
// And returns a status code for that condition.
// Returns [0, nil] if there are no limiting conditions.
func checkConditionalRequest(header http.Header, obj *Object) (int, error) {
	var (
		ifMatch     *bool
		ifNoneMatch *bool
	)

	if _, reqIfMatch := header[textproto.CanonicalMIMEHeaderKey("If-Match")]; reqIfMatch {
		var eval = header.Get("If-Match") == obj.ETag
		ifMatch = &eval
	}

	if _, reqIfNoneMatch := header[textproto.CanonicalMIMEHeaderKey("If-None-Match")]; reqIfNoneMatch {
		var eval = header.Get("If-None-Match") != obj.ETag
		ifNoneMatch = &eval
	}

	// Check if the object has not been modified since the requested date.
	if reqModifiedSince := header.Get("If-Modified-Since"); reqModifiedSince != "" {
		ifModifiedSinceTime, err := time.Parse(http.TimeFormat, reqModifiedSince)
		if err != nil {
			return 0, &Error{
				ErrorCode: InvalidArgument,
				Message:   "Invalid value for If-Modified-Since.",
			}
		}

		ifModifiedSince := ifModifiedSinceTime.After(obj.LastModified)

		if ifMatch != nil {
			if *ifMatch && !ifModifiedSince {
				return 0, nil
			}
		}

		if !ifModifiedSince {
			return http.StatusNotModified, nil
		}
	}

	// Check if the object has not been modified since the requested date.
	if reqUnmodifiedSince := header.Get("If-Unmodified-Since"); reqUnmodifiedSince != "" {
		ifUnmodifiedSinceTime, err := time.Parse(http.TimeFormat, reqUnmodifiedSince)
		if err != nil {
			return 0, &Error{
				ErrorCode: InvalidArgument,
				Message:   "Invalid value for If-Unmodified-Since.",
			}
		}

		ifUnmodifiedSince := obj.LastModified.Before(ifUnmodifiedSinceTime)

		if ifNoneMatch != nil {
			if !*ifNoneMatch && ifUnmodifiedSince {
				return http.StatusNotModified, nil
			}
		}

		if !ifUnmodifiedSince {
			return http.StatusPreconditionFailed, nil
		}
	}

	if ifMatch != nil && !*ifMatch {
		return http.StatusPreconditionFailed, nil
	}

	if ifNoneMatch != nil && !*ifNoneMatch {
		return http.StatusNotModified, nil
	}

	return 0, nil
}

type closeProxy struct {
	io.Reader
	closer func() error
}

func (cp *closeProxy) Close() error {
	return cp.closer()
}

func limitRange(r *http.Request, obj *Object) error {
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		return nil
	}

	ranges, err := http_range.ParseRange(rangeHeader, obj.Size)
	// Only one range request is supported
	if err != nil || len(ranges) != 1 {
		return &Error{
			ErrorCode: InvalidRange,
			Message:   "The requested range is not valid for the request. Try another range.",
		}
	}

	obj.Range = &ranges[0]

	// Seek object to target start range
	seek, ok := obj.ReadCloser.(io.Seeker)
	if !ok {
		return &Error{
			ErrorCode: InvalidRequest,
			Message:   "Ranged requests are not supported for this object.",
		}
	}

	_, err = seek.Seek(obj.Range.Start, 0)
	if err != nil {
		return &Error{
			ErrorCode: InvalidRange,
			Message:   "Unable to access object at start range.",
		}
	}

	// Limit reader to end of range
	rc := obj.ReadCloser
	obj.ReadCloser = &closeProxy{
		Reader: io.LimitReader(rc, obj.Range.Length),
		closer: rc.Close,
	}

	return nil
}

// seekOrRefresh moves the current read pointer to the start of the file.
// If f does not implement io.Seeker then the file is closed, and re-opened from the given filesystem.
func seekOrRefresh(f fs.File, from fs.FS, name string) (fs.File, error) {
	// If file can be seeked then seek it
	if seeker, ok := f.(io.Seeker); ok {
		_, err := seeker.Seek(0, 0)
		return f, err
	}

	// Otherwise, close and reopen the file
	_ = f.Close()
	return from.Open(name)
}

// guessContentType attempts to guess the content type from the input reader.
// It always returns a valid MIME type.
// It returns true if at least some data was read from the reader.
func guessContentType(r io.Reader) (string, bool) {
	head := make([]byte, 261)
	n, _ := io.ReadFull(r, head) // error can be safely ignored

	t, _ := filetype.Match(head)
	mt := t.MIME.Value

	if mt == "" {
		mt = "binary/octet-stream"
	}

	return mt, n > 0
}

func stat(ctx *RequestContext, key string) (*Object, error) {
	f, err := ctx.Filesystem.Open(key)
	if err != nil {
		return nil, unwrapFsError(err)
	}

	contentType, mustRefresh := guessContentType(f)

	if mustRefresh {
		// If file needs refreshing after guessing the content type then do so
		f, err = seekOrRefresh(f, ctx.Filesystem, key)
		if err != nil {
			return nil, unwrapFsError(err)
		}
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, unwrapFsError(err)
	}

	obj := &Object{
		Size:         fi.Size(),
		ReadCloser:   f,
		LastModified: fi.ModTime().UTC(),
		ContentType:  contentType,
	}

	err = limitRange(ctx.Request, obj)
	if err != nil {
		return nil, err
	}

	return obj, nil
}
