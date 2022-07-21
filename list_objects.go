package ls3

import (
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

func listObjectsMaxKeys(r *http.Request) (int, error) {
	maxKeysQuery := r.URL.Query().Get("max-keys")
	if maxKeysQuery == "" {
		return 1000, nil
	}

	maxKeys, err := strconv.Atoi(maxKeysQuery)

	if err != nil || maxKeys < 0 {
		return 0, &Error{
			ErrorCode: InvalidArgument,
			Message:   "Invalid value for max-keys",
		}
	}

	return maxKeys, nil
}

func listObjectsUrlEncodingType(r *http.Request) error {
	if encodingTypeQuery := r.URL.Query().Get("encoding-type"); encodingTypeQuery != "" {
		if encodingTypeQuery != "url" {
			return &Error{
				ErrorCode: InvalidArgument,
				Message:   "Only \"url\" is supported for encoding-type",
			}
		}
	}

	return nil
}

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

func NewBucketIterator(fs fs.FS) *BucketIterator {
	return &BucketIterator{
		IsTruncated: false,
		Continue:    "",
		fs:          fs,
		prefixes:    make(map[string]struct{}),
	}
}

type BucketIterator struct {
	IsTruncated bool
	Continue    string

	seekObject string
	fs         fs.FS
	prefixes   map[string]struct{}
}

func (it *BucketIterator) CommonPrefixes() (prefixes []CommonPrefixes) {
	var commonPrefixKeys = make([]string, 0, len(it.prefixes))
	for k := range it.prefixes {
		commonPrefixKeys = append(commonPrefixKeys, k)
	}

	sort.Strings(commonPrefixKeys)

	prefixes = make([]CommonPrefixes, 0, len(commonPrefixKeys))
	for _, k := range commonPrefixKeys {
		prefixes = append(prefixes, CommonPrefixes{
			Prefix: k,
		})
	}

	return
}

// Seek sets the starting object key to begin seeking during the next PrefixScan.
// It set, all objects will be discarded until the first occurrence of after.
func (it *BucketIterator) Seek(after string) {
	it.seekObject = after
}

func (it *BucketIterator) PrefixScan(prefix string, delimiter string, maxKeys int) ([]Contents, error) {
	var (
		contents     []Contents
		basePath     string
		objectPrefix string
		shouldSkip   = it.seekObject != ""
	)

	if prefix != "" {
		basePath, objectPrefix = path.Split(prefix)
	}

	var scanPath = strings.Trim(basePath, "/")
	if scanPath == "" {
		scanPath = "."
	}

	_ = fs.WalkDir(it.fs, scanPath, func(filePath string, d fs.DirEntry, err error) error {
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

		// It an iteration seek is requested,
		// then ignore all objects until the object path equals the seek object
		if shouldSkip {
			if objectPath == it.seekObject {
				shouldSkip = false
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
				if delimiter == "/" {
					it.prefixes[encodePath(objectPath+"/")] = struct{}{}
					return fs.SkipDir
				}
			}

			return nil
		}

		// If a delimiter is provided, check if this relpath contains the delimiter.
		// If it does then don't add the object as a key, but instead add it to the list of common prefixes.
		if delimiter != "" {
			ix := strings.Index(relPath, delimiter)
			if ix > -1 {
				it.prefixes[encodePath(prefix+relPath[:ix])] = struct{}{}
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

		contents = append(contents, Contents{
			LastModified: fi.ModTime().UTC(),
			Size:         int(fi.Size()),
			Key:          encodePath(objectPath),
		})

		canContinue := len(contents) < maxKeys

		// If number of objects exceeds maxKeys then set result to be truncated.
		// Continue from the next object after this one.
		if !canContinue {
			it.IsTruncated = true
			it.Continue = objectPath
			return errEndOfIteration
		}

		return nil
	})

	return contents, nil
}
