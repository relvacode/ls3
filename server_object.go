package ls3

import (
	"errors"
	"github.com/gotd/contrib/http_range"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

type Object struct {
	io.ReadCloser

	Size         int64
	Range        *http_range.Range
	LastModified time.Time
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

func stat(ctx *RequestContext) (*Object, error) {
	key, err := urlPathObjectKey(ctx.URL.Path)
	if err != nil {
		return nil, err
	}

	f, err := ctx.Filesystem.Open(key)
	if err != nil {
		return nil, unwrapFsError(err)
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
	}

	err = limitRange(ctx.Request, obj)
	if err != nil {
		return nil, err
	}

	return obj, nil
}
