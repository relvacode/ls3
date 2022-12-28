package ls3

import "io/fs"

type BucketFilesystemProvider interface {
	// ListBuckets lists all available filesystemProvider in the provider.
	ListBuckets() ([]string, error)

	// Open returns a filesystem for a given bucket name.
	Open(bucket string) (fs.FS, error)
}

// SingleBucketFilesystem implements BucketFilesystemProvider that
// always returns the same filesystem for any bucket name provided.
type SingleBucketFilesystem struct {
	fs.FS
}

// ListBuckets always returns the same bucket name.
// The actual name doesn't matter, as the provider will always return the same filesystem.
func (p *SingleBucketFilesystem) ListBuckets() ([]string, error) {
	return []string{"any"}, nil
}

func (p *SingleBucketFilesystem) Open(_ string) (fs.FS, error) {
	return p.FS, nil
}

type SubdirBucketFilesystem struct {
	fs.FS
}

// ListBuckets returns all subdirectories of the base filesystem.
func (p *SubdirBucketFilesystem) ListBuckets() ([]string, error) {
	entries, err := fs.ReadDir(p.FS, ".")
	if err != nil {
		return nil, &Error{
			ErrorCode: InternalError,
			Message:   "Unable to list filesystemProvider at this time.",
		}
	}

	var buckets []string
	for _, entry := range entries {
		if !entry.IsDir() {
			// Ignore non-directories
			continue
		}

		buckets = append(buckets, entry.Name())
	}

	return buckets, nil
}

// Open returns a subdirectory of the base filesystem for each bucket.
// The error NoSuchBucket is returned if fs.Stat of the bucket path returns an error.
// The error InvalidBucketState is returned if fs.Sub returns an error.
func (p *SubdirBucketFilesystem) Open(bucket string) (fs.FS, error) {
	fi, err := fs.Stat(p.FS, bucket)
	if err != nil || !fi.IsDir() {
		return nil, &Error{
			ErrorCode: NoSuchBucket,
			Message:   "The specified bucket does not exist.",
		}
	}

	sub, err := fs.Sub(p.FS, bucket)
	if err != nil {
		return nil, &Error{
			ErrorCode: InvalidBucketState,
			Message:   "The request is not valid for the current state of the bucket.",
		}
	}

	return sub, nil
}
