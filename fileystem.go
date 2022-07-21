package ls3

import "io/fs"

// BucketLookup is a function that when given a bucket name, it returns a filesystem for that bucket.
type BucketLookup func(bucket string) (fs.FS, error)

// SingleBucketFilesystem returns a BucketLookup that always returns the same filesystem for all buckets
func SingleBucketFilesystem(fileSystem fs.FS) BucketLookup {
	return func(_ string) (fs.FS, error) {
		return fileSystem, nil
	}
}

// SubdirBucketFilesystem returns a BucketLookup that returns a subdirectory of the base filesystem for each bucket.
// The error NoSuchBucket is returned if fs.Stat of the bucket path returns an error.
// The error InvalidBucketState is returned if fs.Sub returns an error.
func SubdirBucketFilesystem(base fs.FS) BucketLookup {
	return func(bucket string) (fs.FS, error) {
		_, err := fs.Stat(base, bucket)
		if err != nil {
			return nil, &Error{
				ErrorCode: NoSuchBucket,
				Message:   "The specified bucket does not exist.",
			}
		}

		sub, err := fs.Sub(base, bucket)
		if err != nil {
			return nil, &Error{
				ErrorCode: InvalidBucketState,
				Message:   "The request is not valid for the current state of the bucket.",
			}
		}

		return sub, nil
	}
}
