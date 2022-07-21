package ls3

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// errEndOfIteration is a special sentinel error used for walking filesystem paths in ListObjectsV2.
var errEndOfIteration = errors.New("end iteration")

func (s *Server) ListObjectsV2(ctx *RequestContext) *Error {
	type Contents struct {
		ChecksumAlgorithm string
		ETag              string
		Key               string
		LastModified      time.Time
		Size              int
		StorageClass      string
	}

	type CommonPrefixes struct {
		Prefix string
	}

	type ListBucketResult struct {
		XMLName               xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
		Name                  string
		Prefix                string
		Delimiter             string
		MaxKeys               int
		IsTruncated           bool
		EncodingType          string
		Contents              []Contents
		CommonPrefixes        []CommonPrefixes
		ContinuationToken     string
		NextContinuationToken string
		StartAfter            string
	}

	var query = ctx.URL.Query()

	var maxKeys = 1000

	if maxKeysQuery := query.Get("max-keys"); maxKeysQuery != "" {
		var err error
		maxKeys, err = strconv.Atoi(maxKeysQuery)

		if err != nil || maxKeys < 0 {
			return &Error{
				ErrorCode: InvalidArgument,
				Message:   "Invalid value for max-keys",
			}
		}
	}

	// encoding-type is always URL
	if encodingTypeQuery := query.Get("encoding-type"); encodingTypeQuery != "" {
		if encodingTypeQuery != "url" {
			return &Error{
				ErrorCode: InvalidArgument,
				Message:   "Only \"url\" is supported for encoding-type",
			}
		}
	}

	var result = ListBucketResult{
		Name:              ctx.Bucket,
		Prefix:            query.Get("prefix"),
		MaxKeys:           maxKeys,
		Delimiter:         query.Get("delimiter"),
		ContinuationToken: query.Get("continuation-token"),
		StartAfter:        query.Get("start-after"),
		IsTruncated:       false,
		EncodingType:      "url",
	}

	var basePath string
	var objectPrefix string

	if result.Prefix != "" {
		basePath, objectPrefix = path.Split(result.Prefix)
	}

	var continuationPath string

	if result.ContinuationToken != "" {
		continuationPathBytes, err := base64.StdEncoding.DecodeString(result.ContinuationToken)
		if err != nil {
			return &Error{
				ErrorCode: InvalidArgument,
				Message:   "You provided an invalid continuation-token.",
			}
		}

		continuationPath = string(continuationPathBytes)
	}

	// Appends object fs.FileInfo to response contents.
	// Returns false if max keys is exceeded.
	var appendObjectContents = func(name string, fi fs.FileInfo) bool {
		result.Contents = append(result.Contents, Contents{
			LastModified: fi.ModTime().UTC(),
			Size:         int(fi.Size()),
			Key:          encodePath(name),
		})

		return len(result.Contents) < maxKeys
	}

	var scanPath = strings.Trim(basePath, "/")
	if scanPath == "" {
		scanPath = "."
	}

	var shouldSkipStartAfter = result.StartAfter != ""
	var shouldSkipContinuation = continuationPath != ""
	var commonPrefix = make(map[string]struct{})

	_ = fs.WalkDir(ctx.Filesystem, scanPath, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {

			// Unwrap error looking for common filesystem errors
			for unwrap := err; unwrap != nil; unwrap = errors.Unwrap(unwrap) {
				switch unwrap {
				case syscall.EPERM:
					return fs.SkipDir
				}
			}

			return err
		}

		var relPath = strings.Trim(strings.TrimPrefix(filePath, scanPath), "/")
		var objectPath = path.Join(basePath, relPath)

		// If a start after was provided,
		// Skip until this the object path is equal to the start after keu.
		if shouldSkipStartAfter {
			if objectPath == result.StartAfter {
				shouldSkipStartAfter = false
			}
			return nil
		}

		// If a continuation token was provided,
		// Skip until the object path is equal to the continuation token.
		if shouldSkipContinuation {
			if objectPath == continuationPath {
				shouldSkipContinuation = false
			}
			return nil
		}

		// Directory handling
		if d.IsDir() {
			// Inner directory pruning, as long as this path is not the root path
			if filePath != scanPath {
				// If entry is a directory, and an object prefix is set,
				// Signal to WalkDir that this directory should be skipped if it doesn't have the prefix
				if objectPrefix != "" && !strings.HasPrefix(relPath, objectPrefix) {
					return fs.SkipDir
				}

				// If entry is a directory, but not the root, and the delimiter is "/"
				// then we can skip this directory entirely, adding it to the common prefixes.
				if result.Delimiter == "/" {
					commonPrefix[encodePath(objectPath+"/")] = struct{}{}
					return fs.SkipDir
				}
			}

			return nil
		}

		// If a delimiter is provided, check if this relpath contains the delimiter.
		// If it does then don't add the object as a key, but instead add it to the list of common prefixes.
		if result.Delimiter != "" {
			ix := strings.Index(relPath, result.Delimiter)
			if ix > -1 {
				commonPrefix[encodePath(result.Prefix+relPath[:ix])] = struct{}{}
				return nil
			}
		}

		// File is an object
		// Ignore if it doesn't have the prefix
		if objectPrefix != "" && !strings.HasPrefix(relPath, objectPrefix) {
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		// If number of objects exceeds maxKeys then set result to be truncated.
		// Continue from the next object after this one.
		if !appendObjectContents(objectPath, fi) {
			result.IsTruncated = true
			result.NextContinuationToken = base64.StdEncoding.EncodeToString([]byte(objectPath))
			return errEndOfIteration
		}

		return nil
	})

	// Set common prefixes
	var commonPrefixKeys = make([]string, 0, len(commonPrefix))
	for k := range commonPrefix {
		commonPrefixKeys = append(commonPrefixKeys, k)
	}
	sort.Strings(commonPrefixKeys)

	result.CommonPrefixes = make([]CommonPrefixes, 0, len(commonPrefixKeys))
	for _, k := range commonPrefixKeys {
		result.CommonPrefixes = append(result.CommonPrefixes, CommonPrefixes{
			Prefix: k,
		})
	}

	ctx.SendXML(http.StatusOK, &result)
	return nil
}
